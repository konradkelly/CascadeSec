"""The RecordStore conformance suite (portable-runtime-spec §4). Every store
runs every test, and a store that fails one is not an adapter: a store
that skips a condition passes every happy-path test and corrupts review
state under concurrency.

G1-G9 are each written as the operation the code that depends on them
performs, so a failure names what would break. The rest pin down the
semantics those rely on: an update creates the item, a condition on a
missing item fails without creating it, a failed write writes nothing."""

import threading

import pytest

from cascadesec_core.records import Absent, AbsentOr, Conflict, Exists, Missing, PathError, StatusIn, StatusIs

PR = "PR#gh-1-2"


def finding(n=1):
    return PR, f"FINDING#{n:016x}"


# ---------- G1: a rescan keeps review state ----------

def scan_write(store, title, now):
    """iac-scanner's _write_findings: the tool's fields always, review
    state only if absent, and a stale no-longer-detected mark removed."""
    return store.update(*finding(), set={"title": title, "rule_id": "AWS-0086", "line_range": [3, 9],
                                         "last_seen_at": now, "updated_at": now},
                        set_if_absent={"created_at": now, "status": "raw", "control_mappings": [],
                                       "proposed_fix": None},
                        remove=["no_longer_detected", "iac_type"])


def test_g1_a_rescan_keeps_status_mappings_fix_and_created_at(make_store):
    store = make_store()
    first = scan_write(store, "old title", "t1")
    assert (first["status"], first["created_at"], first["proposed_fix"]) == ("raw", "t1", None)

    store.update(*finding(), set={"status": "approved", "control_mappings": [{"control_id": "2.1.5"}],
                                  "proposed_fix": {"diff": "-a\n+b", "self_check": {"passed": True}},
                                  "no_longer_detected": "t2", "iac_type": "terraform"})
    again = scan_write(store, "new title", "t3")

    assert again == store.get(*finding())
    assert again["status"] == "approved"
    assert again["control_mappings"] == [{"control_id": "2.1.5"}]
    assert again["proposed_fix"] == {"diff": "-a\n+b", "self_check": {"passed": True}}
    assert again["created_at"] == "t1"
    assert (again["title"], again["last_seen_at"]) == ("new title", "t3")
    assert "no_longer_detected" not in again and "iac_type" not in again


# ---------- G2: no-longer-detected is marked once ----------

def test_g2_a_later_scan_cannot_move_the_no_longer_detected_date(make_store):
    store = make_store()
    scan_write(store, "t", "t1")
    store.update(*finding(), set={"no_longer_detected": "t2"}, condition=Missing("no_longer_detected"))
    with pytest.raises(Conflict):
        store.update(*finding(), set={"no_longer_detected": "t3"}, condition=Missing("no_longer_detected"))
    assert store.get(*finding())["no_longer_detected"] == "t2"


# ---------- G3: a fix is reopened only if it is still as read ----------

def test_g3_a_reopen_fails_when_the_status_moved_since_it_was_read(make_store):
    store = make_store()
    store.put({"pk": PR, "sk": finding()[1], "status": "fix-proposed"})
    read = store.get(*finding())
    store.update(*finding(), set={"status": "approved"})        # a reviewer, in between
    with pytest.raises(Conflict):
        store.update(*finding(), set={"status": "mapped"}, condition=StatusIs(read["status"]))
    assert store.get(*finding())["status"] == "approved"


# ---------- G4: one commit request per id ----------

def test_g4_a_second_commit_request_with_the_same_id_is_refused(make_store):
    store = make_store()
    request = {"pk": PR, "sk": "COMMIT#r1", "status": "requested", "requested_by": "a"}
    store.put(request, unless_exists=True)
    with pytest.raises(Conflict):
        store.put({**request, "requested_by": "b"}, unless_exists=True)
    assert store.get(PR, "COMMIT#r1")["requested_by"] == "a"


# ---------- G5: the committer claims a request exactly once ----------

def test_g5_of_many_concurrent_claims_exactly_one_wins(make_store):
    make_store().put({"pk": PR, "sk": "COMMIT#r1", "status": "requested"})
    stores = [make_store() for _ in range(8)]
    start, won, lost = threading.Barrier(len(stores)), [], []

    def claim(i, store):
        start.wait()
        try:
            store.update(PR, "COMMIT#r1", set={"status": "committing", "claimed_by": i},
                         condition=StatusIs("requested"))
            won.append(i)
        except Conflict:
            lost.append(i)

    threads = [threading.Thread(target=claim, args=(i, s)) for i, s in enumerate(stores)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(won) == 1 and len(lost) == len(stores) - 1
    assert make_store().get(PR, "COMMIT#r1")["claimed_by"] == won[0]


# ---------- G6: a finished request is never overwritten ----------

def test_g6_a_late_finisher_cannot_overwrite_an_ending(make_store):
    store = make_store()
    store.put({"pk": PR, "sk": "COMMIT#r1", "status": "committing"})
    store.update(PR, "COMMIT#r1", set={"status": "committed", "commit_sha": "abc"},
                 condition=StatusIs("committing"))
    with pytest.raises(Conflict):                       # a twin's _finish
        store.update(PR, "COMMIT#r1", set={"status": "failed"}, condition=StatusIs("committing"))
    with pytest.raises(Conflict):                       # the failure backstop
        store.update(PR, "COMMIT#r1", set={"status": "failed", "reason": "timed out"},
                     condition=AbsentOr(StatusIn("requested", "committing")))
    assert store.get(PR, "COMMIT#r1")["status"] == "committed"


def test_g6_the_backstop_records_a_request_that_never_got_written(make_store):
    store = make_store()
    store.update(PR, "COMMIT#r2", set={"status": "failed", "reason": "never recorded"},
                 condition=AbsentOr(StatusIn("requested", "committing")))
    assert store.get(PR, "COMMIT#r2")["status"] == "failed"


# ---------- G7: a click resolves only a fix that was proposed or resolved ----------

def test_g7_a_click_approval_resolves_only_a_proposed_or_resolved_fix(make_store):
    store = make_store()
    store.put({"pk": PR, "sk": finding(1)[1], "status": "fix-proposed"})
    store.put({"pk": PR, "sk": finding(2)[1], "status": "rejected"})
    for n in (1, 2):
        try:
            store.update(*finding(n), set={"status": "resolved"},
                         condition=StatusIn("fix-proposed", "resolved"))
        except Conflict:
            pass
    assert [store.get(*finding(n))["status"] for n in (1, 2)] == ["resolved", "rejected"]


# ---------- G8: committed only on a record that has a fix ----------

def test_g8_committed_is_recorded_only_where_there_is_a_fix(make_store):
    store = make_store()
    store.put({"pk": PR, "sk": finding(1)[1], "proposed_fix": {"diff": "d"}})
    store.put({"pk": PR, "sk": finding(2)[1], "status": "raw"})
    store.update(*finding(1), set={"proposed_fix.committed": {"sha": "abc"}}, condition=Exists("proposed_fix"))
    with pytest.raises(Conflict):
        store.update(*finding(2), set={"proposed_fix.committed": {"sha": "abc"}}, condition=Exists("proposed_fix"))
    assert store.get(*finding(1))["proposed_fix"] == {"diff": "d", "committed": {"sha": "abc"}}
    assert "proposed_fix" not in store.get(*finding(2))


# ---------- G9: a query returns every item, sorted by sk ----------

def test_g9_a_query_returns_every_item_under_the_prefix_in_sk_order(make_store):
    """Past DynamoDB's 1 MB page: 1,100 items of ~1.2 KB. The latest review
    event, found by sorting on sk, decides whether a prerequisite is met
    (review-api _unmet_prerequisites), so a lost page or a wrong order is a
    wrong review decision."""
    store = make_store()
    pages = _count_pages(store)
    padding = "x" * 1200
    for n in reversed(range(1100)):
        store.put({"pk": PR, "sk": f"EVENT#{n:05d}", "n": n, "padding": padding})
    store.put({"pk": PR, "sk": "FINDING#a"})
    store.put({"pk": "PR#other", "sk": "EVENT#00000"})

    events = store.query(PR, "EVENT#")
    assert [e["n"] for e in events] == list(range(1100))
    assert pages() != 1, "the query fit one page, so it did not test paging"
    assert [i["sk"] for i in store.query(PR)] == [f"EVENT#{n:05d}" for n in range(1100)] + ["FINDING#a"]


def test_a_query_can_limit_what_each_item_carries(make_store):
    store = make_store()
    store.put({"pk": PR, "sk": "FINDING#a", "status": "raw", "file": "s3.tf", "proposed_fix": {"diff": "d"}})
    assert store.query(PR, "FINDING#", attributes=["status", "file"]) == [
        {"pk": PR, "sk": "FINDING#a", "status": "raw", "file": "s3.tf"}]


# ---------- what the guarantees rest on ----------

def test_an_update_creates_the_item_when_there_is_none(make_store):
    store = make_store()
    assert store.update(*finding(), set={"title": "t"}) == {"pk": PR, "sk": finding()[1], "title": "t"}


@pytest.mark.parametrize("condition", [StatusIs("raw"), StatusIn("raw"), Exists("status")])
def test_a_condition_on_a_missing_item_fails_without_creating_it(make_store, condition):
    store = make_store()
    with pytest.raises(Conflict):
        store.update(*finding(), set={"status": "mapped"}, condition=condition)
    assert store.get(*finding()) is None


def test_missing_and_absent_hold_for_a_missing_item(make_store):
    store = make_store()
    store.update(*finding(1), set={"a": 1}, condition=Missing("a"))
    store.update(*finding(2), set={"a": 1}, condition=Absent())
    with pytest.raises(Conflict):
        store.update(*finding(2), set={"a": 2}, condition=Absent())
    assert [store.get(*finding(n))["a"] for n in (1, 2)] == [1, 1]


def test_a_path_under_a_missing_map_is_refused_and_nothing_is_written(make_store):
    store = make_store()
    store.put({"pk": PR, "sk": finding()[1], "status": "raw"})
    with pytest.raises(PathError):
        store.update(*finding(), set={"status": "mapped", "proposed_fix.stale_reason": "r"})
    assert store.get(*finding()) == {"pk": PR, "sk": finding()[1], "status": "raw"}


def test_values_come_back_as_they_went_in(make_store):
    store = make_store()
    item = {"pk": PR, "sk": finding()[1], "line_range": [3, 9], "score": 0.1, "big": 2**53 + 1,
            "flag": False, "nothing": None, "empty": "", "nested": {"list": [{"n": 1}, "s"], "m": {}}}
    store.put(item)
    got = store.get(*finding())
    assert got == item
    assert type(got["line_range"][0]) is int and type(got["score"]) is float


def test_a_put_without_unless_exists_replaces_the_whole_item(make_store):
    store = make_store()
    store.put({"pk": PR, "sk": finding()[1], "a": 1, "b": 2})
    store.put({"pk": PR, "sk": finding()[1], "a": 3})
    assert store.get(*finding()) == {"pk": PR, "sk": finding()[1], "a": 3}


def test_changing_what_a_store_returned_does_not_change_the_store(make_store):
    store = make_store()
    item = {"pk": PR, "sk": finding()[1], "fix": {"chain": [1]}}
    store.put(item)
    item["fix"]["chain"].append(2)
    store.get(*finding())["fix"]["chain"].append(3)
    store.query(PR)[0]["fix"]["chain"].append(4)
    assert store.get(*finding())["fix"] == {"chain": [1]}


def _count_pages(store):
    """How many requests the store's queries made: DynamoDB's adapter sends
    one per page; the memory store has none to count."""
    table = getattr(store, "table", None)
    if table is None:
        return lambda: None
    calls, query = [], table.query

    def counting(**kwargs):
        calls.append(kwargs)
        return query(**kwargs)

    table.query = counting
    return lambda: len([c for c in calls if c["KeyConditionExpression"].count("begins_with")])
