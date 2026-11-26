"""Tests for run_fix_eval.py's scoring. No AWS, no model, no terraform."""

import pathlib
import shutil

import pytest

import run_fix_eval as fe


def item(status="needs-human-only", **fix):
    base = {"finding_id": "f1", "file": "case/main.tf", "target_type": "terraform",
            "source": "checkov", "rule_id": "CKV_AWS_1", "resource": "r", "status": status}
    if fix is not None and status != "superseded":
        base["proposed_fix"] = {"cleared": True, "diff": "", **fix}
    return base


def test_outcomes():
    assert fe.outcome(item("fix-proposed")) == fe.PASSED
    assert fe.outcome(item()) == fe.HELD
    assert fe.outcome({"status": "superseded"}) == fe.SUPERSEDED
    assert fe.outcome({"status": "mapped"}) == fe.NOT_DRAFTED
    assert fe.outcome({"status": "not-drafted", "proposed_fix": None,
                       "not_drafted_reason": "file draft budget reached (8 of 8)"}) == fe.NOT_DRAFTED


def test_gates_follow_the_handlers_order():
    fix = {"cleared": False, "self_check_new_findings": ["checkov:X"], "dropped_resources": ["a.b"],
           "assumptions": ["a"], "questions": [{"answer": "unknown"}, {"answer": "no"}]}
    assert fe.gates(fix) == ["not cleared", "introduced a finding", "deleted a resource",
                             "assumption", "unanswered question"]


def test_suppression_and_scan_errors_skip_the_rescan_verdict():
    # Both return before the self-check, so cleared=False there means
    # "never scanned", not "missed the finding".
    assert fe.gates({"cleared": False, "suppression_attempt": ["+ # tfsec:ignore"]}) == ["suppression"]
    assert fe.gates({"cleared": False, "scan_errors": ["x"], "assumptions": ["a"]}) == ["scan error", "assumption"]


def test_an_answered_question_does_not_hold():
    assert fe.gates({"cleared": True, "questions": [{"answer": "no"}, {"answer": "yes"}]}) == []


def test_row_names_the_first_gate_only_when_held():
    held = fe.row(item(assumptions=["a"], cleared=False))
    assert held["held_by"] == "not cleared" and held["gates"] == ["not cleared", "assumption"]
    assert fe.row(item("fix-proposed"))["held_by"] is None


def test_change_key_ignores_alignment_and_order():
    a = "--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n-  name = \"q\"\n+  name                    = \"q\"\n+  sqs_managed_sse_enabled = true\n"
    b = "--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n-  name = \"q\"\n+  sqs_managed_sse_enabled = true\n+  name = \"q\"\n"
    c = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-  name = \"q\"\n+  name = \"r\"\n"
    assert fe.change_key(a) != fe.change_key(c)
    # Different alignment is a different line, so a and b differ too; the
    # key ignores runs of whitespace inside a line, not what is on it.
    assert fe.change_key(b) == fe.change_key(b.replace("= \"q\"", "=  \"q\""))


def test_summary_counts_clean_clears_before_the_assumption_gates():
    rows = [fe.row(item("fix-proposed")),
            fe.row(item(assumptions=["a"])),
            fe.row(item(cleared=False)),
            fe.row({"finding_id": "s", "file": "case/main.tf", "source": "c", "rule_id": "r",
                    "status": "superseded"})]
    s = fe.summarize(rows)
    assert s["drafted"] == 3 and s["cleared_cleanly"] == 2
    assert s["held_by"] == {"assumption": 1, "not cleared": 1}
    assert s["outcomes"] == {"passed": 1, "held": 2, "superseded": 1}


def run(pr, *rows):
    return {"pr_id": pr, "rows": list(rows)}


def r(fid, outcome, change="c1", language="terraform"):
    return {"finding_id": fid, "file": "x/main.tf", "rule": "c:R", "outcome": outcome,
            "change": change, "language": language, "gates": []}


def test_consistency_counts_passes_and_whether_they_agree():
    runs = [run("1", r("a", fe.PASSED), r("b", fe.PASSED, "c1")),
            run("2", r("a", fe.PASSED), r("b", fe.PASSED, "c2")),
            run("3", r("a", fe.HELD), r("b", fe.PASSED, "c1"))]
    out = {c["finding_id"]: c for c in fe.consistency(runs)}
    assert out["a"]["passed"] == 2 and out["a"]["same_change"] is True
    assert out["b"]["passed"] == 3 and out["b"]["same_change"] is False


def test_consistency_skips_findings_seen_once():
    assert fe.consistency([run("1", r("a", fe.PASSED)), run("2", r("b", fe.PASSED))]) == []


def test_audit_sample_is_stratified_sized_and_repeatable():
    rows = ([r(f"t{i}", fe.HELD) for i in range(30)] + [r(f"p{i}", fe.PASSED) for i in range(10)]
            + [r("k", fe.HELD, language="kubernetes")] + [r("s", fe.SUPERSEDED)])
    sample = fe.audit_sample([run("1", *rows)], 8)
    assert len(sample) == 8
    kinds = {(s["language"], s["outcome"]) for s in sample}
    assert kinds == {("terraform", "held"), ("terraform", "passed"), ("kubernetes", "held")}
    assert all(s["verdict"] is None for s in sample)
    assert sample == fe.audit_sample([run("1", *rows)], 8)


@pytest.mark.skipif(shutil.which("patch") is None, reason="needs patch")
def test_corrected_applies_the_chain_in_order(tmp_path):
    src = tmp_path / "src" / "case"
    src.mkdir(parents=True)
    (src / "main.tf").write_text('a = 1\nb = 2\n')
    d1 = "--- a/case/main.tf\n+++ b/case/main.tf\n@@ -1,2 +1,2 @@\n-a = 1\n+a = 10\n b = 2\n"
    d2 = "--- a/case/main.tf\n+++ b/case/main.tf\n@@ -1,2 +1,2 @@\n a = 10\n-b = 2\n+b = 20\n"
    rows = {"f1": {"finding_id": "f1", "file": "case/main.tf", "applies_after": [], "diff": d1},
            "f2": {"finding_id": "f2", "file": "case/main.tf", "applies_after": ["f1"], "diff": d2}}
    out = fe.corrected(rows["f2"], rows, tmp_path / "src", tmp_path / "w")
    assert out.read_text() == "a = 10\nb = 20\n"
    # Without its prerequisite, the second diff does not apply.
    alone = dict(rows["f2"], applies_after=[])
    assert fe.corrected(alone, rows, tmp_path / "src", tmp_path / "w2") is None


def test_an_unchanged_file_is_no_change_not_a_broken_chain(tmp_path, monkeypatch):
    (tmp_path / "case").mkdir()
    (tmp_path / "case" / "main.tf").write_text('resource "x" "y" {}\n')
    monkeypatch.setattr(fe, "terraform_valid", lambda d: True)
    rows = [{"finding_id": "f1", "file": "case/main.tf", "language": "terraform",
             "outcome": fe.HELD, "diff": "", "applies_after": []}]
    fe.validity(rows, tmp_path)
    assert rows[0]["valid"] == "no change"
