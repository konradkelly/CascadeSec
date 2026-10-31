"""The RecordStore port (portable-runtime-spec §3): findings, review events,
commit requests and PR metadata, as items keyed by `pk` and `sk`.

The item model is DynamoDB's as the handlers use it today, kept exactly,
so the dashboard and every reader are unchanged (P3). What changes is that
the operations are named instead of written as expression strings, so that
a store other than DynamoDB can perform them, and so the guarantees the
review process depends on (§4, G1-G9) can be tested on every store alike
(tests/test_records_conformance.py).

  get(pk, sk) -> item | None
  query(pk, sk_prefix="", attributes=None) -> [item]
      every item under pk whose sk starts with sk_prefix, sorted by sk,
      however many there are (G9); `attributes` limits what each carries
  put(item, unless_exists=False)
      unless_exists: Conflict if an item with that key is already there
  update(pk, sk, set=None, set_if_absent=None, remove=(), condition=None) -> item
      creates the item when there is none, as DynamoDB's update does,
      unless a condition says otherwise; returns the item as written

What a value may be: str, int, float, bool, None, and lists and dicts of
them. A number comes back as int when it is whole, float otherwise, from
every store (DynamoDB's Decimal stays inside its adapter).

A key in `set` may be a path into a map, "proposed_fix.committed". Its
parent must exist: setting a path under a missing map raises PathError
rather than inventing the map, as DynamoDB does.

A condition that does not hold raises Conflict and writes nothing. An
adapter decides nothing (§2): it stores what it is told, when the
condition says it may.
"""

from dataclasses import dataclass


class Conflict(Exception):
    """A write's condition did not hold, so nothing was written."""


class PathError(ValueError):
    """`set` named a path under a map the item does not have."""


# ---------- conditions ----------
#
# Each says what it means as `holds(item)`, where item is None when there is
# no item with that key. Stores that cannot evaluate them natively (memory,
# SQLite, Postgres) evaluate this, inside the same lock or transaction as
# the write; the DynamoDB adapter translates them to the expressions they
# replaced.

@dataclass(frozen=True)
class StatusIs:
    """The item's status is this one. Missing item: does not hold."""
    value: str

    def holds(self, item):
        return item is not None and item.get("status") == self.value


@dataclass(frozen=True)
class StatusIn:
    values: tuple

    def __init__(self, *values):
        object.__setattr__(self, "values", tuple(values))

    def holds(self, item):
        return item is not None and item.get("status") in self.values


@dataclass(frozen=True)
class Exists:
    """The item has this attribute. Missing item: does not hold."""
    attribute: str

    def holds(self, item):
        return item is not None and self.attribute in item


@dataclass(frozen=True)
class Missing:
    """The item lacks this attribute, or there is no item."""
    attribute: str

    def holds(self, item):
        return item is None or self.attribute not in item


@dataclass(frozen=True)
class Absent:
    """There is no item with this key."""

    def holds(self, item):
        return item is None


@dataclass(frozen=True)
class AbsentOr:
    """No item yet, or the item meets `condition`."""
    condition: object

    def holds(self, item):
        return item is None or self.condition.holds(item)


# ---------- the port ----------

class RecordStore:
    """What an adapter implements. Not a framework: four operations, each
    the one the handlers already perform."""

    def get(self, pk, sk):
        raise NotImplementedError

    def query(self, pk, sk_prefix="", attributes=None):
        raise NotImplementedError

    def put(self, item, unless_exists=False):
        raise NotImplementedError

    def update(self, pk, sk, set=None, set_if_absent=None, remove=(), condition=None):
        raise NotImplementedError


def apply_update(item, pk, sk, set=None, set_if_absent=None, remove=()):
    """The item an update writes, from the item it reads (None when there
    is none). For the stores that apply updates themselves; DynamoDB's
    adapter has DynamoDB do it. Mutates nothing it is given."""
    new = _copy(item) if item is not None else {"pk": pk, "sk": sk}
    for path, value in (set or {}).items():
        *parents, leaf = path.split(".")
        target = new
        for name in parents:
            if not isinstance(target.get(name), dict):
                raise PathError(f"{path}: {name} is not a map on {pk} {sk}")
            target = target[name]
        target[leaf] = _copy(value)
    for name, value in (set_if_absent or {}).items():
        new.setdefault(name, _copy(value))
    for name in remove:
        new.pop(name, None)
    return new


def project(item, attributes):
    """The item with only `attributes` (and its key), or whole when None."""
    if attributes is None:
        return item
    keep = set(attributes) | {"pk", "sk"}
    return {k: v for k, v in item.items() if k in keep}


def _copy(value):
    """A deep copy of a value as a store holds it: what a caller does to its
    copy afterwards never reaches the store, as with any store over a wire."""
    if isinstance(value, dict):
        return {k: _copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_copy(v) for v in value]
    return value
