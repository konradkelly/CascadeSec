"""Calls to review-api (docs/cli-spec.md §10), as the signed-in person.

The ID token is the bearer, as for the dashboard: the JWT authorizer checks
`aud`, and only the ID token carries it (auth.py). Each request takes the
session through auth.current_session, so a token near expiry is refreshed
before it is sent rather than failing in flight.

An HTTP status becomes an exit code here, once, so no command has to decide
what a 404 means:

  400, 409   the API refused, and said why      REFUSED (1); the body is kept
  401        the API refused the session        SERVICE (4); sign in again
  403        signed in, but not allowed         SERVICE (4)
  404        no such PR, finding or content     USAGE (2): the argument was wrong
  other      the service failed                 SERVICE (4)

400 is a refusal rather than a fault because of what review-api sends it
for: an edit identical to the fix's base ("nothing to record"), or an edit
with no content. Both are about what was submitted, and both carry a
reason the person can act on.

A refusal keeps the response body on the error, because review-api puts the
reason there -- unmet prerequisites, a moved commit plan -- and the CLI's
job is to print it rather than swallow it (§10).
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from cascadesec import __version__, auth
from cascadesec.errors import REFUSED, SERVICE, USAGE, CliError

HTTP_TIMEOUT_SECONDS = 30


class ApiError(CliError):
    def __init__(self, message, code, status, body):
        super().__init__(message, code)
        self.status = status
        self.body = body


def _send(method, url, token, body=None):
    """One request, returning (status, parsed JSON or None). Module-level so
    tests replace it rather than a socket."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": f"cascadesec-cli/{__version__}",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise CliError(f"could not reach {urllib.parse.urlsplit(url).hostname}: {e}", SERVICE) from None
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, None


class Client:
    def __init__(self, settings, store, now=time.time):
        self.settings = settings.require("api_url", "auth_domain", "client_id")
        self.store = store
        self.now = now

    def get(self, *segments):
        return self.request("GET", *segments)

    def request(self, method, *segments, body=None):
        # Path parameters are quoted whole: a PR id is free text to the API,
        # and a `/` in one must not become another route.
        path = "/".join(urllib.parse.quote(str(s), safe="") for s in segments)
        url = f"{self.settings.api_url}/{path}"
        token = auth.current_session(self.settings, self.store, now=self.now)["id_token"]
        status, parsed = _send(method, url, token, body)
        if 200 <= status < 300:
            return parsed
        raise _error_for(status, parsed, method, path)


def _error_for(status, body, method, path):
    reason = _reason(body) or f"HTTP {status}"
    if status == 401:
        return ApiError("review-api did not accept the session; run `cascadesec login`",
                        SERVICE, status, body)
    if status == 403:
        return ApiError(f"not allowed: {reason}", SERVICE, status, body)
    if status == 404:
        return ApiError(reason, USAGE, status, body)
    if status in (400, 409):
        return ApiError(reason, REFUSED, status, body)
    return ApiError(f"review-api failed on {method} /{path}: {reason}", SERVICE, status, body)


def _reason(body):
    if isinstance(body, dict):
        # review-api says {"error": ...}; API Gateway's own 401 says {"message": ...}.
        return body.get("error") or body.get("message")
    return None
