"""A RecordStore in memory: for tests, and the reference the conformance
suite holds every other store to. One lock around each read-check-write,
which is the shape the SQLite and Postgres adapters take with a
transaction (portable-runtime-spec §3)."""

import threading

from cascadesec_core.records import Conflict, RecordStore, _copy, apply_update, project


class MemoryRecordStore(RecordStore):
    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def get(self, pk, sk):
        with self._lock:
            item = self._items.get((pk, sk))
            return _copy(item) if item is not None else None

    def query(self, pk, sk_prefix="", attributes=None):
        with self._lock:
            found = [item for (p, s), item in self._items.items() if p == pk and s.startswith(sk_prefix)]
            return [project(_copy(item), attributes) for item in sorted(found, key=lambda i: i["sk"])]

    def put(self, item, unless_exists=False):
        key = (item["pk"], item["sk"])
        with self._lock:
            if unless_exists and key in self._items:
                raise Conflict(f"{key[0]} {key[1]} already exists")
            self._items[key] = _copy(item)

    def update(self, pk, sk, set=None, set_if_absent=None, remove=(), condition=None):
        with self._lock:
            current = self._items.get((pk, sk))
            if condition is not None and not condition.holds(current):
                raise Conflict(f"{pk} {sk}: {condition} does not hold")
            new = apply_update(current, pk, sk, set, set_if_absent, remove)
            self._items[(pk, sk)] = new
            return _copy(new)
