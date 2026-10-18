"""Signing a person in: authorization code + PKCE against the Cognito Hosted
UI, with a loopback redirect (docs/cli-spec.md §11.1). The same flow as the
dashboard's auth/pkce.ts, with a local listener where the dashboard has a
route.

**Fixed ports.** Cognito matches a redirect URI against the client's
registered callback URLs and documents no port wildcard, so the CLI can't
take any free port as RFC 8252 §7.3 would allow. It tries CALLBACK_PORTS in
order; cognito.tf registers the same three (tests/test_terraform_agreement.py
holds them together). Plain http is allowed only for `localhost` -- not
127.0.0.1 -- so the redirect names localhost and the listener binds both
127.0.0.1 and ::1, since the browser may resolve it to either.

**Why a squatter on a port is not a leak.** Anything else listening there
receives the code, but the code is useless without the PKCE verifier, which
never leaves this process. The `state` check is what stops a stray or forged
callback being taken for ours.

**No device-code flow.** User pools offer only the code, implicit and
client-credentials grants. For a machine with no browser (SSH), --no-browser
prints the URL; the person opens it anywhere and pastes back the URL the
browser was sent to. Its page fails to load, but the code is in it.

**Which token is the credential.** The ID token: the JWT authorizer checks
`aud`, and only the ID token carries it (api_gateway.tf). Claims are decoded
here only to show them -- the API verifies the signature, the CLI never
trusts what it decodes for anything but display.
"""

import base64
import errno
import hashlib
import http.server
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

from cascadesec.errors import USAGE, SERVICE, CliError

# Must match cognito.tf's cli_interactive callback_urls.
CALLBACK_PORTS = (47811, 47812, 47813)
CALLBACK_PATH = "/callback"
SCOPES = "openid email profile"
LOGIN_TIMEOUT_SECONDS = 300
# Refresh an ID token this close to expiry, so it doesn't lapse in flight.
REFRESH_MARGIN_SECONDS = 120
HTTP_TIMEOUT_SECONDS = 15

DONE_PAGE = (
    b"<!doctype html><meta charset=utf-8><title>CascadeSec</title>"
    b"<body style='font-family:system-ui;margin:3em'>"
    b"<h1>Signed in</h1><p>You can close this tab and return to the terminal.</p>"
)
FAILED_PAGE = (
    b"<!doctype html><meta charset=utf-8><title>CascadeSec</title>"
    b"<body style='font-family:system-ui;margin:3em'>"
    b"<h1>Sign-in failed</h1><p>The terminal says why.</p>"
)


# ---------- PKCE and the authorize URL ----------

def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def code_challenge(verifier):
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def new_pkce():
    verifier = _b64url(secrets.token_bytes(32))
    return verifier, code_challenge(verifier)


def redirect_uri(port):
    return f"http://localhost:{port}{CALLBACK_PATH}"


def authorize_url(settings, redirect, state, challenge):
    query = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": settings.client_id,
        "redirect_uri": redirect,
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return f"https://{settings.auth_domain}/oauth2/authorize?{query}"


# ---------- the token endpoint ----------

def _post_form(url, fields):
    """POST a form, return (status, parsed JSON or None). Module-level so
    tests replace it rather than a socket."""
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise CliError(f"could not reach {urllib.parse.urlsplit(url).hostname}: {e}", SERVICE) from None
    try:
        return status, json.loads(body) if body else None
    except ValueError:
        return status, None


def _token_request(settings, fields):
    status, body = _post_form(
        f"https://{settings.auth_domain}/oauth2/token",
        {"client_id": settings.client_id, **fields},
    )
    if status == 200 and isinstance(body, dict) and body.get("id_token"):
        return body
    error = body.get("error") if isinstance(body, dict) else None
    return {"_error": error or f"HTTP {status}"}


def _session_from(tokens, refresh_token, signed_in_at):
    id_token = tokens["id_token"]
    return {
        "id_token": id_token,
        # Cognito rotates refresh tokens only when the client asks it to; when
        # it does, the old one stops working, so a new one always replaces it.
        "refresh_token": tokens.get("refresh_token") or refresh_token,
        "expires_at": int(claims(id_token).get("exp", 0)),
        "signed_in_at": signed_in_at,
    }


def claims(id_token):
    """The token's payload, unverified. For display only (module docstring)."""
    try:
        payload = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        raise CliError("the stored ID token is malformed; run `cascadesec login`", SERVICE) from None


# ---------- login ----------

def login(settings, store, *, open_browser=True, out=None, prompt=input, open_url=webbrowser.open,
          now=time.time):
    """Run the flow, store the session, return its claims."""
    settings.require("auth_domain", "client_id")
    out = out or _stderr
    verifier, challenge = new_pkce()
    state = secrets.token_urlsafe(24)

    listener = _Listener.start(state) if open_browser else None
    if open_browser and listener is None:
        out(f"Ports {', '.join(map(str, CALLBACK_PORTS))} are all in use; "
            "falling back to pasting the redirect URL.")
    port = listener.port if listener else CALLBACK_PORTS[0]
    redirect = redirect_uri(port)
    url = authorize_url(settings, redirect, state, challenge)

    try:
        if listener:
            out("Opening your browser to sign in. If it doesn't open, visit:")
            out(f"  {url}")
            open_url(url)
            params = listener.wait(LOGIN_TIMEOUT_SECONDS)
            if params is None:
                raise CliError(
                    f"no sign-in arrived within {LOGIN_TIMEOUT_SECONDS // 60} minutes. "
                    "Run `cascadesec login --no-browser` to paste the redirect URL instead.",
                    SERVICE,
                )
        else:
            out("Open this URL in a browser and sign in:")
            out(f"  {url}")
            out("The browser then goes to a localhost page that won't load. "
                "Copy that page's full URL from the address bar.")
            params = parse_pasted(prompt("Paste it here: "), state)
    finally:
        if listener:
            listener.stop()

    code = _code_from(params, state)
    tokens = _token_request(settings, {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect,
        "code_verifier": verifier,
    })
    if "_error" in tokens:
        raise CliError(f"Cognito refused the sign-in: {tokens['_error']}", SERVICE)
    if not tokens.get("refresh_token"):
        raise CliError("Cognito returned no refresh token; check the client allows ALLOW_REFRESH_TOKEN_AUTH",
                       SERVICE)
    session = _session_from(tokens, None, int(now()))
    store.save(session)
    return claims(session["id_token"])


def parse_pasted(text, state):
    text = (text or "").strip()
    parsed = urllib.parse.urlsplit(text)
    if parsed.path != CALLBACK_PATH or not parsed.query:
        raise CliError("that isn't the redirect URL: expected http://localhost:<port>/callback?code=...", USAGE)
    return dict(urllib.parse.parse_qsl(parsed.query))


def _code_from(params, state):
    if params.get("error"):
        raise CliError(f"sign-in failed: {params['error']}: {params.get('error_description', '')}".rstrip(": "),
                       SERVICE)
    # Compared in constant time out of habit; the state is single-use either way.
    if not secrets.compare_digest(params.get("state", ""), state):
        raise CliError("the redirect's state doesn't match this sign-in; start again with `cascadesec login`",
                       SERVICE)
    if not params.get("code"):
        raise CliError("the redirect carried no authorization code", SERVICE)
    return params["code"]


class _Listener:
    """One-shot HTTP listener for the redirect, on 127.0.0.1 and ::1."""

    def __init__(self, servers, port, state):
        self.servers, self.port, self.state = servers, port, state
        self.params = None
        self.arrived = threading.Event()

    @classmethod
    def start(cls, state):
        for port in CALLBACK_PORTS:
            servers = _bind_both(port)
            if servers:
                listener = cls(servers, port, state)
                for server in servers:
                    server.listener = listener
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                return listener
        return None

    def wait(self, timeout):
        return self.params if self.arrived.wait(timeout) else None

    def stop(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()


class _Server(http.server.HTTPServer):
    # A port another process holds must read as taken, and the two systems
    # need opposite settings to get that:
    #
    #   - Windows: SO_REUSEADDR would let this bind on top of a live
    #     listener, so it stays off, and SO_EXCLUSIVEADDRUSE also stops
    #     anything binding on top of us.
    #   - Linux and macOS: SO_REUSEADDR never permits a second listener on
    #     the same address, but without it a port this process just served a
    #     callback on sits in TIME_WAIT for about a minute and cannot be
    #     bound. Off, a second `login` within a minute skipped 47811, and a
    #     third ran out of ports (seen in CI, which runs logins back to back).
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class _Server6(_Server):
    address_family = socket.AF_INET6


def _bind_both(port):
    """Servers on 127.0.0.1 and ::1 at `port`, or None if it's taken.

    IPv6 missing altogether is fine -- then localhost can't resolve to ::1
    either. ::1 held by something else is not: the browser could be sent
    there, so the port is treated as taken."""
    try:
        v4 = _Server(("127.0.0.1", port), _Handler)
    except OSError:
        return None
    if not socket.has_ipv6:
        return [v4]
    try:
        return [v4, _Server6(("::1", port), _Handler)]
    except OSError as e:
        if e.errno in _NO_IPV6_ERRNOS:
            return [v4]
        v4.server_close()
        return None


_NO_IPV6_ERRNOS = {errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT, 10047, 10049}  # + WSAEAFNOSUPPORT, WSAEADDRNOTAVAIL


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        listener = self.server.listener
        parsed = urllib.parse.urlsplit(self.path)
        # Browsers also ask for /favicon.ico; anything but the callback is
        # not ours to answer.
        if parsed.path != CALLBACK_PATH or listener.arrived.is_set():
            self.send_error(404)
            return
        params = dict(urllib.parse.parse_qsl(parsed.query))
        ok = not params.get("error") and params.get("code") and secrets.compare_digest(
            params.get("state", ""), listener.state)
        page = DONE_PAGE if ok else FAILED_PAGE
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)
        listener.params = params
        listener.arrived.set()

    def log_message(self, *args):
        pass  # the query string carries the code; keep it off the terminal


# ---------- a usable session ----------

def current_session(settings, store, now=time.time):
    """The stored session with an ID token good for at least
    REFRESH_MARGIN_SECONDS, refreshing it if needed."""
    settings.require("auth_domain", "client_id")
    session = store.load()
    if not session or not session.get("refresh_token"):
        raise CliError("not signed in; run `cascadesec login`", SERVICE)
    if session.get("expires_at", 0) - now() > REFRESH_MARGIN_SECONDS:
        return session
    tokens = _token_request(settings, {"grant_type": "refresh_token", "refresh_token": session["refresh_token"]})
    if "_error" in tokens:
        if tokens["_error"] == "invalid_grant":
            # Expired or revoked: the session is over, and keeping it would
            # make every later command fail the same way, slower.
            store.clear()
            raise CliError("your session has expired or was revoked; run `cascadesec login`", SERVICE)
        raise CliError(f"could not refresh the session: {tokens['_error']}", SERVICE)
    session = _session_from(tokens, session["refresh_token"], session.get("signed_in_at"))
    store.save(session)
    return session


def logout(settings, store):
    """Revoke the refresh token, then forget the session. Returns
    (had_session, revoked).

    Revocation is attempted first and its failure reported, not raised: the
    local copy goes either way, because a person who asked to sign out
    should not be left signed in by a network error. An ID token already
    issued stays valid until it expires (60 minutes) -- revocation stops
    refreshes, not tokens in flight."""
    settings.require("auth_domain", "client_id")
    session = store.load()
    revoked = False
    if session and session.get("refresh_token"):
        try:
            status, _ = _post_form(f"https://{settings.auth_domain}/oauth2/revoke", {
                "token": session["refresh_token"],
                "client_id": settings.client_id,
            })
            revoked = status == 200
        except CliError:
            revoked = False
    had = store.clear()
    return had, revoked


def _stderr(line):
    print(line, file=sys.stderr, flush=True)
