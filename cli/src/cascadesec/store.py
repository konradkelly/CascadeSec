"""The signed-in session, in the OS credential store (docs/cli-spec.md §8,
§11.1): Windows Credential Manager, macOS Keychain, or Secret Service.

One session per deployment. The account name is the Hosted UI domain and the
client id, so signing in to one deployment does not sign out of another.

**Chunked.** Windows Credential Manager refuses a secret over 1,280
characters (CredWrite error 1783, "The stub received bad data"; measured
2026-10-13 with keyring 25.7.0 on Windows 11), and a Cognito refresh token
alone is longer than that. The session's JSON is split into numbered entries,
and a header entry holding the count is written last, so a save interrupted
part-way leaves the previous header pointing at a set that still loads -- or
at a chunk that no longer parses, which reads as signed out, never as
someone else's half-session.

There is no fallback to a file when no keyring is available (a headless
Linux box without Secret Service). Writing the refresh token to a dotfile is
the thing §11.1 rules out, so that is an error with the fix in it.
"""

import json

import keyring
import keyring.errors

from cascadesec.errors import SERVICE, CliError

SERVICE_NAME = "cascadesec"
# Under the 1,280 limit with room to spare; JSON of a session is ASCII.
CHUNK_CHARS = 1000


class SessionStore:
    def __init__(self, auth_domain, client_id, backend=keyring):
        self.account = f"{auth_domain}|{client_id}"
        self.backend = backend

    def load(self):
        header = self._get(self.account)
        if header is None:
            return None
        try:
            count = json.loads(header)["chunks"]
            parts = [self._get(f"{self.account}#{i}") for i in range(count)]
            if any(p is None for p in parts):
                return None
            session = json.loads("".join(parts))
        except (ValueError, KeyError, TypeError):
            return None
        return session if isinstance(session, dict) else None

    def save(self, session):
        blob = json.dumps(session, separators=(",", ":"))
        chunks = [blob[i:i + CHUNK_CHARS] for i in range(0, len(blob), CHUNK_CHARS)]
        old = self._count()
        for i, chunk in enumerate(chunks):
            self._call(self.backend.set_password, SERVICE_NAME, f"{self.account}#{i}", chunk)
        self._call(self.backend.set_password, SERVICE_NAME, self.account, json.dumps({"chunks": len(chunks)}))
        for i in range(len(chunks), old):
            self._delete(f"{self.account}#{i}")

    def clear(self):
        """Remove the session. True if there was one."""
        count = self._count()
        existed = self._delete(self.account)
        for i in range(count):
            self._delete(f"{self.account}#{i}")
        return existed

    def _count(self):
        header = self._get(self.account)
        try:
            return int(json.loads(header)["chunks"]) if header else 0
        except (ValueError, KeyError, TypeError):
            return 0

    def _get(self, name):
        return self._call(self.backend.get_password, SERVICE_NAME, name)

    def _delete(self, name):
        try:
            self._call(self.backend.delete_password, SERVICE_NAME, name)
            return True
        except keyring.errors.PasswordDeleteError:
            return False

    @staticmethod
    def _call(fn, *args):
        try:
            return fn(*args)
        except keyring.errors.PasswordDeleteError:
            raise
        except keyring.errors.NoKeyringError:
            raise CliError(
                "no OS keyring is available to keep the session in. On Linux, install and unlock "
                "a Secret Service provider (gnome-keyring or KWallet). The CLI does not fall back "
                "to a file.",
                SERVICE,
            ) from None
        except keyring.errors.KeyringError as e:
            raise CliError(f"the OS keyring refused: {e}", SERVICE) from None
