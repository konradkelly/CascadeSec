import base64
import json

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
