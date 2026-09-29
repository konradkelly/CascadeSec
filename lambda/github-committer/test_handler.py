"""Tests for github-committer's handler. KMS, S3, DynamoDB and GitHub are all
mocked -- no AWS or network calls."""

import hashlib

import pytest

import handler


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


HEAD = "a\nb\nc\nd\n"
FIXED = {"1": "a\nb\nC\nd\n", "2": "a\nB\nC\nd\n", "3": "A\nB\nC\nd\n"}


def _fix(fid, diff=None, applies_after=(), base=HEAD, verified=True, file="f.tf", **extra):
    return {"finding_id": fid, "file": file, "rule_id": f"R-{fid}", "status": "resolved",
            "proposed_fix": {"diff": diff or f"diff-{fid}", "self_check_passed": verified,
                             "base_sha256": _h(base) if base else None,
                             "applies_after": [{"finding_id": a, "diff_sha256": _h(f"diff-{a}")}
                                               for a in applies_after],
                             **extra}}


def _plan(findings, actions=None, head=HEAD, fixes=None):
    actions = {f["finding_id"]: "approved" for f in findings} if actions is None else actions
    fixes = {f"fixes/p/{i}/f.tf": text for i, text in FIXED.items()} if fixes is None else fixes
    read_head = (lambda path: (head, None)) if isinstance(head, str) else head
    return handler.plan_commit("p", findings, actions, fixes.get, read_head)


# ======================================================================
# plan_commit: which fixes, and which file content
# ======================================================================

def test_an_approved_fix_on_an_unchanged_file_is_committed_whole():
    [plan] = _plan([_fix("1")])
    assert plan["outcome"] == "commit" and plan["reason"] is None
    assert plan["content"] == FIXED["1"]
    # The diff the reviewer confirms is head to tip, the change the commit makes.
    assert "-c\n+C\n" in plan["diff"] and plan["diff"].startswith("--- a/f.tf\n+++ b/f.tf\n")
    assert plan["chain"] == [{"finding_id": "1", "rule_id": "R-1", "verified": True, "edited": False}]


@pytest.mark.parametrize("latest", ["rejected", "reopened", None])
def test_only_a_fix_whose_latest_decision_accepts_it_is_planned(latest):
    # The event log, not status: approve then reject leaves status
    # "resolved" while the decision standing on it is a rejection.
    assert _plan([_fix("1")], actions={"1": latest} if latest else {}) == []


def test_a_committed_fix_or_one_no_longer_detected_is_not_planned_again():
    committed = _fix("1", committed={"sha": "c" * 40, "request_id": "r", "at": "t"})
    gone = {**_fix("2"), "no_longer_detected": "t"}
    assert _plan([committed, gone]) == []


def test_the_tip_is_the_longest_approved_chain():
    [plan] = _plan([_fix("1"), _fix("2", applies_after=["1"]), _fix("3", applies_after=["1", "2"])])
    assert plan["tip"] == "3" and [c["finding_id"] for c in plan["chain"]] == ["1", "2", "3"]
    assert plan["content"] == FIXED["3"] and plan["left_out"] == []


def test_a_fix_drafted_on_an_unapproved_one_is_left_out():
    # 2 was drafted on 1's content; 1 is not approved, so 2's file carries
    # a change nobody said yes to. 3 stands alone and is committed.
    findings = [_fix("1"), _fix("2", applies_after=["1"]), _fix("3")]
    [plan] = _plan(findings, actions={"2": "approved", "3": "approved"})
    assert plan["tip"] == "3" and plan["left_out"] == ["R-2"]


def test_a_fix_drafted_on_a_link_edited_since_is_left_out():
    # 1 was edited after 2 was drafted on it: its diff is no longer the one
    # 2's chain recorded.
    findings = [_fix("1", diff="diff-1-edited"), _fix("2", applies_after=["1"])]
    [plan] = _plan(findings)
    assert plan["tip"] == "1" and plan["left_out"] == ["R-2"]


def test_a_chain_from_before_links_carried_hashes_fails_closed():
    legacy = _fix("2")
    legacy["proposed_fix"]["applies_after"] = ["1"]
    [plan] = _plan([_fix("1"), legacy], actions={"2": "approved"})
    assert plan["outcome"] == "held" and plan["left_out"] == ["R-2"]


def test_an_edited_or_unverified_link_is_committed_and_labelled():
    # write-back-spec §5.5 (W4): a person approved it; the push scan is the
    # check it did not get. Labelled so nobody mistakes it for verified.
    findings = [_fix("1", verified=False), _fix("2", applies_after=["1"], verified=False)]
    [plan] = _plan(findings, actions={"1": "approved", "2": "edited"})
    assert plan["outcome"] == "commit"
    assert [(c["verified"], c["edited"]) for c in plan["chain"]] == [(False, False), (False, True)]


# ======================================================================
# plan_commit: the base check
# ======================================================================

KEY_AT_A = 'resource "aws_kms_key" "reports" {\n  description = "exports"\n}\n'
ALIAS = '\nresource "aws_kms_alias" "reports" {\n  name = "alias/reports"\n}\n'
ROTATED_AT_A = KEY_AT_A.replace("}\n", "  enable_key_rotation = true\n}\n")


def test_a_fix_drafted_before_the_file_changed_is_held_not_committed_over_it():
    """cascadesec-testbed #3 (write-back-spec §8). Rotation was drafted on
    commit A; commit B appended an alias. Committing A's corrected file over
    B deletes the alias, and it did once, as a posted suggestion."""
    fix = {**_fix("kms", base=KEY_AT_A), "file": "reports.tf"}
    [plan] = handler.plan_commit("p", [fix], {"kms": "approved"},
                                 {"fixes/p/kms/reports.tf": ROTATED_AT_A}.get,
                                 lambda path: (KEY_AT_A + ALIAS, None))
    assert plan["outcome"] == "held" and "changed since" in plan["reason"]
    assert plan["content"] is None and plan["diff"] is None


def test_a_fix_with_no_recorded_base_is_held():
    [plan] = _plan([_fix("1", base=None)])
    assert plan["outcome"] == "held" and "Draft fixes again" in plan["reason"]


def test_a_head_that_already_has_the_fix_is_already_committed():
    # A retried request, or a person who applied the suggestions: nothing
    # to write, and the base no longer matches because the fix is in it.
    [plan] = _plan([_fix("1")], head=FIXED["1"])
    assert plan["outcome"] == "already" and plan["content"] is None


def test_a_head_that_cannot_be_read_is_held_with_its_reason():
    [plan] = _plan([_fix("1")], head=lambda path: (None, "a symlink at the PR head"))
    assert plan["outcome"] == "held" and plan["reason"] == "a symlink at the PR head"


def test_a_missing_corrected_file_is_held():
    [plan] = _plan([_fix("1")], fixes={})
    assert plan["outcome"] == "held" and "missing" in plan["reason"]


def test_files_are_planned_independently_and_in_order():
    findings = [_fix("1", file="z.tf"), _fix("2", file="a.tf", base=None)]
    fixes = {"fixes/p/1/z.tf": FIXED["1"], "fixes/p/2/a.tf": FIXED["2"]}
    plans = _plan(findings, fixes=fixes)
    assert [(p["file"], p["outcome"]) for p in plans] == [("a.tf", "held"), ("z.tf", "commit")]
