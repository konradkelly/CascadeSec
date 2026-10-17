import pytest

from cascadesec import config
from cascadesec.errors import USAGE, CliError

SERVER = """
[server]
api_url = "https://api.example.test/"
auth_domain = "https://Auth.Example.test/"
client_id = "from-file"
"""


@pytest.fixture
def home(tmp_path):
    """An env whose user config dir is empty and under tmp_path."""
    return {"APPDATA": str(tmp_path / "appdata"), "XDG_CONFIG_HOME": str(tmp_path / "xdg")}


def write_user_file(env, text):
    path = config.user_config_path(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_repo_file_is_normalised(tmp_path, home):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    # Top-level keys go before [server]; after it, TOML puts them in the table.
    (repo / ".cascadesec.toml").write_text('project = "testbed"\n' + SERVER)
    (repo / "infra" / "modules").mkdir(parents=True)

    s = config.load(cwd=repo / "infra" / "modules", env=home)

    assert s.api_url == "https://api.example.test"
    assert s.auth_domain == "auth.example.test"
    assert s.project == "testbed"
    assert s.sources["client_id"].endswith(".cascadesec.toml")


def test_precedence_user_then_repo_then_env(tmp_path, home):
    write_user_file(home, SERVER.replace("from-file", "from-user"))
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".cascadesec.toml").write_text('[server]\nclient_id = "from-repo"\n')

    assert config.load(cwd=repo, env=home).client_id == "from-repo"
    assert config.load(cwd=repo, env={**home, "CASCADESEC_CLIENT_ID": "from-env"}).client_id == "from-env"
    # The user file still supplies what the repo file doesn't.
    assert config.load(cwd=repo, env=home).auth_domain == "auth.example.test"


def test_a_file_above_the_repository_root_is_not_read(tmp_path, home):
    (tmp_path / ".cascadesec.toml").write_text(SERVER)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    assert config.load(cwd=repo, env=home).client_id is None


@pytest.mark.parametrize("text", [
    '[server]\nclient_id = "x"\nid_token = "eyJ..."\n',
    '[auth]\nrefresh_token = "x"\n',
    'api_secret = "x"\n',
])
def test_a_credential_in_a_file_is_refused(tmp_path, home, text):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".cascadesec.toml").write_text(text)

    with pytest.raises(CliError) as e:
        config.load(cwd=repo, env=home)
    assert e.value.code == USAGE
    assert "credential" in str(e.value)


@pytest.mark.parametrize("key,value", [
    ("CASCADESEC_API", "http://api.example.test"),
    ("CASCADESEC_API", "api.example.test"),
    ("CASCADESEC_AUTH_DOMAIN", "auth.example.test/oauth2"),
])
def test_bad_values_are_refused(tmp_path, home, key, value):
    with pytest.raises(CliError) as e:
        config.load(cwd=tmp_path, env={**home, key: value})
    assert e.value.code == USAGE


def test_http_is_allowed_for_localhost_only(tmp_path, home):
    s = config.load(cwd=tmp_path, env={**home, "CASCADESEC_API": "http://localhost:3000"})
    assert s.api_url == "http://localhost:3000"


def test_require_names_what_is_missing_and_where_to_put_it(tmp_path, home):
    with pytest.raises(CliError) as e:
        config.load(cwd=tmp_path, env=home).require("auth_domain", "client_id")
    assert "CASCADESEC_AUTH_DOMAIN" in str(e.value)
    assert "cli_config" in str(e.value)
    assert e.value.code == USAGE
