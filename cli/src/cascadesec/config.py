"""Where the CLI's settings come from (docs/cli-spec.md §2), lowest
precedence first:

  1. the user's file        %APPDATA%\\cascadesec\\config.toml on Windows,
                            else $XDG_CONFIG_HOME (or ~/.config)/cascadesec/config.toml
  2. the repository's       .cascadesec.toml, the nearest one walking up from
                            the working directory, stopping at the repository root
  3. the environment        CASCADESEC_API, CASCADESEC_AUTH_DOMAIN, CASCADESEC_CLIENT_ID

`terraform output -raw cli_config` prints the [server] table for either file.
None of it is secret: the dashboard ships the same domain and client id in
its bundle.

A credential is never read from a file. The repository's file is committed
and reviewed like code, so a token in it is a token in git history; the
user's file is not a credential store either -- that is the keyring's job
(store.py). A file that tries is refused, not ignored, so the mistake is
found the first time it is made rather than after the push.
"""

import os
import re
import tomllib
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from cascadesec.errors import USAGE, CliError

REPO_FILE = ".cascadesec.toml"

# [server] key -> environment variable.
SERVER_KEYS = {
    "api_url": "CASCADESEC_API",
    "auth_domain": "CASCADESEC_AUTH_DOMAIN",
    "client_id": "CASCADESEC_CLIENT_ID",
}

# Any key whose name says it holds one of these is refused, at any depth.
CREDENTIAL_WORDS = ("token", "secret", "password", "credential")

HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


@dataclass
class Settings:
    api_url: str | None = None
    auth_domain: str | None = None
    client_id: str | None = None
    project: str | None = None
    # [[skip_apps]] from the repository's file: apps local mode is told not
    # to report as unscanned (cli-spec §3.5), each with the reason someone
    # wrote down. {"path": absolute Path, "reason": str, "source": file}.
    skip_apps: list = field(default_factory=list)
    # key -> where its value came from, so an error can name the file to fix.
    sources: dict = field(default_factory=dict)

    def require(self, *keys):
        missing = [k for k in keys if not getattr(self, k)]
        if missing:
            raise CliError(
                "not configured: " + ", ".join(f"{k} ({SERVER_KEYS[k]})" for k in missing) + ". "
                "Put the [server] table from `terraform output -raw cli_config` in "
                f"{user_config_path()} or the repository's {REPO_FILE}, or set the variables.",
                USAGE,
            )
        return self


def user_config_path(env=os.environ):
    if os.name == "nt" and env.get("APPDATA"):
        base = Path(env["APPDATA"])
    else:
        base = Path(env.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "cascadesec" / "config.toml"


def find_repo_file(start):
    """The nearest .cascadesec.toml at or above `start`, not looking past the
    repository root -- a file in a parent of the checkout belongs to
    something else."""
    here = Path(start).resolve()
    for directory in (here, *here.parents):
        candidate = directory / REPO_FILE
        if candidate.is_file():
            return candidate
        if (directory / ".git").exists():
            return None
    return None


def load(cwd=None, env=None):
    env = os.environ if env is None else env
    settings = Settings()
    repo_file = find_repo_file(cwd or os.getcwd())
    for path in (user_config_path(env), repo_file):
        if path is not None and path.is_file():
            _apply_file(settings, path, repository=path == repo_file)
    for key, var in SERVER_KEYS.items():
        if env.get(var):
            _set(settings, key, env[var], f"${var}")
    return settings


def _apply_file(settings, path, repository=False):
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise CliError(f"{path}: not valid TOML: {e}", USAGE) from None
    credential = _credential_key(data)
    if credential:
        raise CliError(
            f"{path}: `{credential}` looks like a credential, and the CLI never reads one from a "
            "file. Remove it; `cascadesec login` keeps the session in the OS keyring.",
            USAGE,
        )
    server = data.get("server", {})
    if not isinstance(server, dict):
        raise CliError(f"{path}: [server] must be a table", USAGE)
    for key in SERVER_KEYS:
        if key in server:
            _set(settings, key, server[key], str(path))
    if "project" in data:
        settings.project = data["project"]
        settings.sources["project"] = str(path)
    if "skip_apps" in data:
        if not repository:
            raise CliError(f"{path}: skip_apps belongs in a repository's {REPO_FILE}, where skipping "
                           "an app is reviewed with the code, not in your own settings", USAGE)
        settings.skip_apps = _skip_apps(data["skip_apps"], path)


def _skip_apps(entries, path):
    """[[skip_apps]] path = "...", reason = "...". The reason is required: an
    app skipped with no reason is a gate quietly disabled, which is what the
    baseline's visible-in-a-diff rule exists to prevent (§6)."""
    if not isinstance(entries, list):
        raise CliError(f"{path}: skip_apps must be an array of tables ([[skip_apps]])", USAGE)
    apps = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise CliError(f"{path}: each [[skip_apps]] entry is a table", USAGE)
        app, reason = entry.get("path"), entry.get("reason")
        if not isinstance(app, str) or not app.strip():
            raise CliError(f"{path}: a [[skip_apps]] entry needs a path", USAGE)
        if not isinstance(reason, str) or not reason.strip():
            raise CliError(f"{path}: skip_apps entry {app!r} needs a reason", USAGE)
        apps.append({"path": (path.parent / app.strip()).resolve(), "reason": reason.strip(),
                     "source": str(path)})
    return apps


def _credential_key(data, prefix=""):
    for key, value in data.items():
        name = f"{prefix}{key}"
        if any(word in key.lower() for word in CREDENTIAL_WORDS):
            return name
        if isinstance(value, dict):
            found = _credential_key(value, name + ".")
            if found:
                return found
    return None


def _set(settings, key, value, source):
    if not isinstance(value, str) or not value.strip():
        raise CliError(f"{source}: {key} must be a non-empty string", USAGE)
    value = value.strip()
    if key == "auth_domain":
        # Accepted as terraform prints it (a bare host) or as a URL.
        value = re.sub(r"^https://", "", value).rstrip("/").lower()
        if not HOSTNAME.match(value):
            raise CliError(f"{source}: auth_domain must be a hostname, got {value!r}", USAGE)
    elif key == "api_url":
        value = value.rstrip("/")
        parsed = urllib.parse.urlsplit(value)
        # The ID token goes to this URL on every request.
        local = parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
        if not (parsed.scheme == "https" and parsed.hostname) and not local:
            raise CliError(f"{source}: api_url must be an https URL, got {value!r}", USAGE)
    setattr(settings, key, value)
    settings.sources[key] = source
