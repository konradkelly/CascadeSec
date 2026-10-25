import base64
import json
import os
import subprocess

import keyring.errors
import pytest

from cascadesec.config import Settings


class FakeKeyring:
    """An in-memory keyring with Windows Credential Manager's limit, so the
    chunking in store.py is exercised against the constraint it exists for."""

    LIMIT = 1280

    def __init__(self):
        self.items = {}

    def get_password(self, service, name):
        return self.items.get((service, name))

    def set_password(self, service, name, value):
        if len(value) > self.LIMIT:
            raise keyring.errors.PasswordSetError("(1783, 'CredWrite', 'The stub received bad data')")
        self.items[(service, name)] = value

    def delete_password(self, service, name):
        if (service, name) not in self.items:
            raise keyring.errors.PasswordDeleteError("not found")
        del self.items[(service, name)]


@pytest.fixture
def backend():
    return FakeKeyring()


@pytest.fixture
def settings():
    return Settings(
        api_url="https://api.example.test",
        auth_domain="auth.example.test",
        client_id="client123",
    )


def make_jwt(**claims):
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{part({'alg': 'RS256'})}.{part(claims)}.sig"


# A Cognito refresh token is an encrypted JWE of about 1,800 characters --
# longer than one keyring entry can hold on Windows.
LONG_REFRESH_TOKEN = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ." + "x" * 1750


# ---------- git and the scanner, for the comparison with an earlier version ----------

class GitRepo:
    """A real repository in a temporary directory: the comparison reads
    history through git itself, so the tests use git rather than a fake."""

    def __init__(self, path):
        self.path = path
        self.git("init", "-q")

    def git(self, *args):
        done = subprocess.run(["git", "-C", str(self.path), "-c", "user.email=t@example.test",
                               "-c", "user.name=t", "-c", "commit.gpgsign=false", *args],
                              capture_output=True, text=True, check=True)
        return done.stdout.strip()

    def write(self, files):
        for rel, text in files.items():
            target = self.path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")

    def stage(self, files):
        self.write(files)
        self.git("add", "--", *files)

    def commit(self, files, message="change"):
        self.stage(files)
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def git_repo(tmp_path, monkeypatch):
    # Never let git find a repository above the test's own.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    monkeypatch.setattr("cascadesec.scan.shutil.which", lambda name: "/usr/bin/docker")
    return GitRepo(tmp_path)


class Scanner:
    """Docker, faked at the subprocess boundary: `now` answers a scan of the
    working tree, `earlier` a scan of an exported earlier version (history.py
    writes it under a cascadesec-earlier- directory), and each earlier scan
    records the files it was given. git passes through to git."""

    def __init__(self, now=(), earlier=(), errors=(), apps=()):
        self.now, self.earlier = list(now), list(earlier)
        self.errors, self.apps = list(errors), list(apps)
        self.calls, self.exported = [], []

    def __call__(self, cmd, **kwargs):
        if cmd[0] == "git":
            return subprocess.run(cmd, **kwargs)
        self.calls.append(cmd)
        mount = cmd[cmd.index("-v") + 1].rsplit(":/src", 1)[0]
        is_earlier = "cascadesec-earlier-" in mount
        if is_earlier:
            self.exported.append(sorted(
                os.path.relpath(os.path.join(d, f), mount).replace(os.sep, "/")
                for d, _, files in os.walk(mount) for f in files))
        result = {"scanned_files": 1, "findings": self.earlier if is_earlier else self.now,
                  "scan_errors": [] if is_earlier else self.errors,
                  "unscanned_apps": [] if is_earlier else self.apps}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(result), "")
