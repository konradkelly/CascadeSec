import io
import json

import pytest
from conftest import make_jwt

from cascadesec import main as cli
from cascadesec.store import SessionStore


@pytest.fixture
def env(tmp_path):
    return {
        "APPDATA": str(tmp_path / "appdata"),
        "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
        "CASCADESEC_AUTH_DOMAIN": "auth.example.test",
        "CASCADESEC_CLIENT_ID": "client123",
    }


def run(argv, env, tmp_path, backend):
    out = io.StringIO()
    code = cli.main(argv, stdout=out, env=env, cwd=tmp_path, backend=backend)
    return code, out.getvalue()


def test_whoami_json(env, tmp_path, backend):
    token = make_jwt(email="r@example.test", exp=4_000_000_000, iat=3_999_996_400,
                     **{"cognito:groups": ["committers"]})
    SessionStore("auth.example.test", "client123", backend=backend).save(
        {"id_token": token, "refresh_token": "r", "expires_at": 4_000_000_000, "signed_in_at": 3_999_990_000})

    code, out = run(["--format", "json", "whoami"], env, tmp_path, backend)

    assert code == 0
    result = json.loads(out)
    assert result["email"] == "r@example.test"
    assert result["groups"] == ["committers"]
    assert result["deployment"] == "auth.example.test"


def test_whoami_table(env, tmp_path, backend):
    token = make_jwt(email="r@example.test", exp=4_000_000_000, iat=3_999_996_400)
    SessionStore("auth.example.test", "client123", backend=backend).save(
        {"id_token": token, "refresh_token": "r", "expires_at": 4_000_000_000})

    code, out = run(["--format", "table", "whoami"], env, tmp_path, backend)

    assert code == 0
    assert "Signed in as   r@example.test" in out
    assert "Groups         (none)" in out


def test_not_signed_in_exits_4(env, tmp_path, backend, capsys):
    code, out = run(["whoami"], env, tmp_path, backend)
    assert code == 4
    assert out == ""
    assert "cascadesec login" in capsys.readouterr().err


def test_unconfigured_exits_2(tmp_path, backend, capsys):
    env = {"APPDATA": str(tmp_path / "a"), "XDG_CONFIG_HOME": str(tmp_path / "x")}
    code, _ = run(["whoami"], env, tmp_path, backend)
    assert code == 2
    assert "cli_config" in capsys.readouterr().err


def test_version_needs_no_configuration(tmp_path, backend):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".cascadesec.toml").write_text("not = [valid")
    code, out = run(["--format", "json", "version"], {}, tmp_path, backend)
    assert code == 0
    assert json.loads(out)["cli"]


def test_logout_when_signed_out(env, tmp_path, backend):
    code, out = run(["--format", "json", "logout"], env, tmp_path, backend)
    assert code == 0
    assert json.loads(out) == {"signed_out": False, "revoked": False}
