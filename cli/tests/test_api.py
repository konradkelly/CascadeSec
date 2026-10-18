import pytest
from conftest import make_jwt

from cascadesec import api
from cascadesec.errors import CliError
from cascadesec.store import SessionStore

TOKEN = make_jwt(email="r@example.test", exp=4_000_000_000)


@pytest.fixture
def client(settings, backend):
    store = SessionStore(settings.auth_domain, settings.client_id, backend=backend)
    store.save({"id_token": TOKEN, "refresh_token": "r", "expires_at": 4_000_000_000})
    return api.Client(settings, store, now=lambda: 3_999_000_000)


def test_sends_the_id_token_and_quotes_path_segments(client, monkeypatch):
    sent = []
    monkeypatch.setattr(api, "_send", lambda m, url, token, body=None: sent.append((m, url, token)) or (200, {"ok": 1}))

    assert client.get("prs", "a/b", "findings") == {"ok": 1}
    assert sent == [("GET", "https://api.example.test/prs/a%2Fb/findings", TOKEN)]


@pytest.mark.parametrize("status,body,code,words", [
    (401, {"message": "Unauthorized"}, 4, "cascadesec login"),
    (403, {"error": "not a committer"}, 4, "not a committer"),
    (404, {"error": "finding not found"}, 2, "finding not found"),
    (409, {"error": "prerequisites unmet", "unmet": ["x"]}, 1, "prerequisites unmet"),
    (500, {"error": "internal error"}, 4, "internal error"),
    (502, None, 4, "HTTP 502"),
])
def test_a_status_becomes_one_exit_code(client, monkeypatch, status, body, code, words):
    monkeypatch.setattr(api, "_send", lambda *a, **k: (status, body))

    with pytest.raises(api.ApiError) as e:
        client.get("prs", "p", "findings")

    assert e.value.code == code
    assert words in str(e.value)
    assert e.value.body == body  # a refusal's reasons are kept for the command to print


def test_needs_the_api_url(settings, backend):
    settings.api_url = None
    with pytest.raises(CliError) as e:
        api.Client(settings, SessionStore("a", "b", backend=backend))
    assert e.value.code == 2
    assert "CASCADESEC_API" in str(e.value)
