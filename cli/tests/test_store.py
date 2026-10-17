from conftest import LONG_REFRESH_TOKEN, FakeKeyring

from cascadesec.store import SERVICE_NAME, SessionStore


def test_a_session_longer_than_one_entry_round_trips(backend):
    store = SessionStore("auth.example.test", "client123", backend=backend)
    session = {"id_token": "a.b.c", "refresh_token": LONG_REFRESH_TOKEN, "expires_at": 1}

    store.save(session)

    assert store.load() == session
    assert all(len(v) <= FakeKeyring.LIMIT for v in backend.items.values())
    assert len(backend.items) > 2  # header plus at least two chunks


def test_a_shorter_session_removes_the_old_chunks(backend):
    store = SessionStore("auth.example.test", "client123", backend=backend)
    store.save({"refresh_token": LONG_REFRESH_TOKEN * 2})
    store.save({"refresh_token": "short"})

    assert store.load() == {"refresh_token": "short"}
    assert set(backend.items) == {(SERVICE_NAME, store.account), (SERVICE_NAME, store.account + "#0")}


def test_a_missing_chunk_reads_as_signed_out(backend):
    store = SessionStore("auth.example.test", "client123", backend=backend)
    store.save({"refresh_token": LONG_REFRESH_TOKEN})
    del backend.items[(SERVICE_NAME, store.account + "#1")]

    assert store.load() is None


def test_deployments_do_not_share_a_session(backend):
    dev = SessionStore("dev.example.test", "c1", backend=backend)
    prod = SessionStore("prod.example.test", "c2", backend=backend)
    dev.save({"refresh_token": "dev"})

    assert prod.load() is None
    assert prod.clear() is False
    assert dev.load() == {"refresh_token": "dev"}


def test_clear_removes_everything(backend):
    store = SessionStore("auth.example.test", "client123", backend=backend)
    store.save({"refresh_token": LONG_REFRESH_TOKEN})

    assert store.clear() is True
    assert backend.items == {}
    assert store.load() is None
