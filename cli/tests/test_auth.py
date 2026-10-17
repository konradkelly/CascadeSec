import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest
from conftest import LONG_REFRESH_TOKEN, make_jwt

from cascadesec import auth
from cascadesec.errors import SERVICE, USAGE, CliError
from cascadesec.store import SessionStore

NOW = 1_800_000_000


def test_code_challenge_matches_rfc7636_appendix_b():
    assert auth.code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == \
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_authorize_url_asks_for_s256_and_a_localhost_redirect(settings):
    url = auth.authorize_url(settings, auth.redirect_uri(47811), "st", "ch")
    parsed = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parsed.query))

    assert parsed.netloc == "auth.example.test" and parsed.path == "/oauth2/authorize"
    assert query["redirect_uri"] == "http://localhost:47811/callback"
    assert query["code_challenge_method"] == "S256"
    assert query["client_id"] == "client123"


class TokenEndpoint:
    """Stands in for Cognito's /oauth2/token and /oauth2/revoke."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, fields):
        self.calls.append((url, fields))
        return self.responses.pop(0)


def tokens(exp=NOW + 3600, refresh=LONG_REFRESH_TOKEN, groups=("committers",)):
    body = {"id_token": make_jwt(email="r@example.test", exp=exp, iat=exp - 3600,
                                 **{"cognito:groups": list(groups)}),
            "access_token": "access"}
    if refresh:
        body["refresh_token"] = refresh
    return 200, body


def browser_that_follows_redirect(code="the-code", state=None, extra=None):
    """A browser that 'signs in' and hits the redirect, as Cognito would."""
    hits = {}

    def open_url(url):
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        params = {"code": code, "state": state if state is not None else query["state"], **(extra or {})}
        callback = query["redirect_uri"] + "?" + urllib.parse.urlencode(params)

        def go():
            try:
                with urllib.request.urlopen(callback, timeout=5) as r:
                    hits["status"] = r.status
            except urllib.error.HTTPError as e:
                hits["status"] = e.code
        threading.Thread(target=go, daemon=True).start()
    return open_url, hits


def test_login_through_the_loopback_listener(settings, backend, monkeypatch):
    endpoint = TokenEndpoint([tokens()])
    monkeypatch.setattr(auth, "_post_form", endpoint)
    store = SessionStore(settings.auth_domain, settings.client_id, backend=backend)
    open_url, hits = browser_that_follows_redirect()

    claims = auth.login(settings, store, open_url=open_url, out=lambda _: None, now=lambda: NOW)

    assert claims["email"] == "r@example.test"
    url, fields = endpoint.calls[0]
    assert url == "https://auth.example.test/oauth2/token"
    assert fields["grant_type"] == "authorization_code"
    assert fields["code"] == "the-code"
    assert fields["redirect_uri"].startswith("http://localhost:4781")
    assert auth.code_challenge(fields["code_verifier"])  # sent, and well-formed
    session = store.load()
    assert session["refresh_token"] == LONG_REFRESH_TOKEN
    assert session["expires_at"] == NOW + 3600
    assert hits["status"] == 200


def test_a_callback_with_the_wrong_state_is_refused(settings, backend, monkeypatch):
    endpoint = TokenEndpoint([])
    monkeypatch.setattr(auth, "_post_form", endpoint)
    store = SessionStore(settings.auth_domain, settings.client_id, backend=backend)
    open_url, hits = browser_that_follows_redirect(state="forged")

    with pytest.raises(CliError, match="state"):
        auth.login(settings, store, open_url=open_url, out=lambda _: None)
    assert endpoint.calls == []  # the code was never exchanged
    assert store.load() is None
    assert hits["status"] == 400


def test_a_busy_port_moves_to_the_next(settings, backend, monkeypatch):
    blocker = auth._bind_both(auth.CALLBACK_PORTS[0])
    assert blocker, "first callback port already in use on this machine"
    try:
        monkeypatch.setattr(auth, "_post_form", TokenEndpoint([tokens()]))
        store = SessionStore(settings.auth_domain, settings.client_id, backend=backend)
        open_url, _ = browser_that_follows_redirect()
        seen = []

        def spy(url):
            seen.append(url)
            open_url(url)

        auth.login(settings, store, open_url=spy, out=lambda _: None)
        assert f"localhost%3A{auth.CALLBACK_PORTS[1]}" in seen[0]
    finally:
        for server in blocker:
            server.server_close()


def test_no_browser_takes_the_pasted_redirect(settings, backend, monkeypatch):
    endpoint = TokenEndpoint([tokens()])
    monkeypatch.setattr(auth, "_post_form", endpoint)
    store = SessionStore(settings.auth_domain, settings.client_id, backend=backend)
    printed = []

    def paste(_prompt):
        url = next(line.strip() for line in printed if "oauth2/authorize" in line)
        state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))["state"]
        return f"http://localhost:47811/callback?code=pasted&state={state}"

    auth.login(settings, store, open_browser=False, out=printed.append, prompt=paste)

    assert endpoint.calls[0][1]["code"] == "pasted"
    assert endpoint.calls[0][1]["redirect_uri"] == "http://localhost:47811/callback"


def test_pasting_something_else_is_a_usage_error():
    with pytest.raises(CliError) as e:
        auth.parse_pasted("https://auth.example.test/login?x=1", "st")
    assert e.value.code == USAGE


def test_cognito_error_on_the_redirect_is_reported(settings, backend, monkeypatch):
    monkeypatch.setattr(auth, "_post_form", TokenEndpoint([]))
    store = SessionStore(settings.auth_domain, settings.client_id, backend=backend)
    open_url, _ = browser_that_follows_redirect(code="", extra={"error": "access_denied"})

    with pytest.raises(CliError, match="access_denied"):
        auth.login(settings, store, open_url=open_url, out=lambda _: None)


def stored(settings, backend, **session):
    store = SessionStore(settings.auth_domain, settings.client_id, backend=backend)
    store.save({"id_token": make_jwt(exp=session.get("expires_at", NOW + 3600)),
                "refresh_token": "old-refresh", "expires_at": NOW + 3600, "signed_in_at": NOW - 10, **session})
    return store


def test_a_fresh_token_is_used_as_is(settings, backend, monkeypatch):
    endpoint = TokenEndpoint([])
    monkeypatch.setattr(auth, "_post_form", endpoint)
    store = stored(settings, backend)

    auth.current_session(settings, store, now=lambda: NOW)
    assert endpoint.calls == []


def test_a_token_near_expiry_is_refreshed_and_the_refresh_token_kept(settings, backend, monkeypatch):
    endpoint = TokenEndpoint([tokens(exp=NOW + 3600, refresh=None)])
    monkeypatch.setattr(auth, "_post_form", endpoint)
    store = stored(settings, backend, expires_at=NOW + 60)

    session = auth.current_session(settings, store, now=lambda: NOW)

    assert endpoint.calls[0][1] == {"client_id": "client123", "grant_type": "refresh_token",
                                    "refresh_token": "old-refresh"}
    assert session["expires_at"] == NOW + 3600
    assert store.load()["refresh_token"] == "old-refresh"
    assert store.load()["signed_in_at"] == NOW - 10


def test_a_rotated_refresh_token_replaces_the_old_one(settings, backend, monkeypatch):
    monkeypatch.setattr(auth, "_post_form", TokenEndpoint([tokens(refresh="new-refresh")]))
    store = stored(settings, backend, expires_at=NOW)

    auth.current_session(settings, store, now=lambda: NOW)
    assert store.load()["refresh_token"] == "new-refresh"


def test_an_expired_session_is_cleared(settings, backend, monkeypatch):
    monkeypatch.setattr(auth, "_post_form", TokenEndpoint([(400, {"error": "invalid_grant"})]))
    store = stored(settings, backend, expires_at=NOW)

    with pytest.raises(CliError, match="login") as e:
        auth.current_session(settings, store, now=lambda: NOW)
    assert e.value.code == SERVICE
    assert store.load() is None


def test_a_service_error_on_refresh_keeps_the_session(settings, backend, monkeypatch):
    monkeypatch.setattr(auth, "_post_form", TokenEndpoint([(500, None)]))
    store = stored(settings, backend, expires_at=NOW)

    with pytest.raises(CliError, match="HTTP 500"):
        auth.current_session(settings, store, now=lambda: NOW)
    assert store.load() is not None


def test_not_signed_in(settings, backend):
    store = SessionStore(settings.auth_domain, settings.client_id, backend=backend)
    with pytest.raises(CliError, match="not signed in"):
        auth.current_session(settings, store)


def test_logout_revokes_then_clears(settings, backend, monkeypatch):
    endpoint = TokenEndpoint([(200, None)])
    monkeypatch.setattr(auth, "_post_form", endpoint)
    store = stored(settings, backend)

    assert auth.logout(settings, store) == (True, True)
    assert endpoint.calls[0] == ("https://auth.example.test/oauth2/revoke",
                                 {"token": "old-refresh", "client_id": "client123"})
    assert store.load() is None


def test_logout_clears_even_when_revoke_fails(settings, backend, monkeypatch):
    def unreachable(url, fields):
        raise CliError("could not reach auth.example.test")
    monkeypatch.setattr(auth, "_post_form", unreachable)
    store = stored(settings, backend)

    assert auth.logout(settings, store) == (True, False)
    assert store.load() is None
