"""The review logic, held to what the dashboard says about the same records
(review.py names each source)."""

from cascadesec import review


def finding(fid, **overrides):
    return {"finding_id": fid, "source": "trivy", "rule_id": "AWS-0086", "file": "s3.tf",
            "status": "raw", **overrides}


# ---------- raw findings ----------

def test_raw_findings_group_by_reason_backlog_first():
    groups = review.group_unmapped([
        finding("a", unmapped_reason="hygiene"),
        finding("b", rule_id="X", unmapped_reason="unreviewed"),
        finding("c", rule_id="Y", unmapped_reason="no-control"),
        finding("d", rule_id="Z"),
        finding("e", status="mapped"),
    ])

    assert [g["reason"] for g in groups] == ["unreviewed", "not-examined", "no-control", "hygiene"]


def test_a_raw_finding_with_no_tag_was_never_examined_not_judged():
    """A GitHub run maps only the changed files; the rest have no verdict."""
    assert review.unmapped_reason(finding("a")) == "not-examined"


def test_one_rule_is_one_row_worst_severity_first():
    (group,) = review.group_unmapped([
        finding("a", file="b.tf", severity="LOW", unmapped_reason="no-control"),
        finding("b", file="a.tf", severity="HIGH", unmapped_reason="no-control"),
        finding("c", file="a.tf", severity="LOW", unmapped_reason="no-control"),
        finding("d", rule_id="AWS-0001", severity="MEDIUM", unmapped_reason="no-control"),
    ])

    assert [r["rule_id"] for r in group["rules"]] == ["AWS-0086", "AWS-0001"]
    first = group["rules"][0]
    assert (first["severity"], first["file_count"], group["finding_count"]) == ("HIGH", 2, 4)
    assert [f["file"] for f in first["findings"]] == ["a.tf", "a.tf", "b.tf"]


def test_the_same_rule_id_from_two_scanners_stays_two_rows():
    (group,) = review.group_unmapped([
        finding("a", rule_id="X-1", unmapped_reason="hygiene"),
        finding("b", rule_id="X-1", source="checkov", unmapped_reason="hygiene"),
    ])
    assert len(group["rules"]) == 2


def test_mapped_share_is_none_for_no_findings_not_zero():
    assert review.mapped_share([]) is None
    assert review.mapped_share([finding("a"), finding("b", status="resolved")]) == 0.5


def test_reason_wording_matches_the_dashboard():
    """Copied from unmapped.ts; the dashboard and the CLI must not describe
    the same group differently. Read from the source so a reword there
    fails here."""
    import pathlib
    import re
    ts = (pathlib.Path(__file__).parents[2] / "dashboard" / "src" / "review" / "unmapped.ts").read_text(encoding="utf-8")
    labels = dict(re.findall(r"^\s+'?([a-z-]+)'?: '([^']+)',$", ts.split("REASON_DESCRIPTIONS")[0], re.M))
    assert labels == review.REASON_LABELS


# ---------- the self-check verdict ----------

def test_a_clean_rescan_held_by_a_gate_is_not_a_failed_fix():
    verdict, detail = review.self_check({"self_check_passed": False, "cleared": True,
                                         "assumptions": ["the bucket is private elsewhere"]})
    assert verdict == "Rescan clean, held for review"
    assert "rests on assumptions" in detail


def test_a_parse_failure_reads_as_unverified_not_as_a_miss():
    verdict, _ = review.self_check({"self_check_passed": False, "cleared": False,
                                    "scan_errors": ["main.tf"]})
    assert verdict == "Fix did not parse"


def test_a_failed_fix_says_both_halves_of_why():
    verdict, detail = review.self_check({"self_check_passed": False, "cleared": False,
                                         "self_check_new_findings": ["x", "y"]})
    assert verdict == "Self-check failed"
    assert detail == "original issue not cleared; 2 new findings introduced"


def test_no_fix_is_no_self_check():
    assert review.self_check(None) == ("No self-check", None)
    assert review.self_check({"diff": "x"}) == ("No self-check", None)


# ---------- prerequisites ----------

def test_unmet_prerequisites_say_which_kind():
    good = "--- a\n+++ b\n+x\n"
    by_id = {
        "ok": finding("ok", status="resolved", proposed_fix={"diff": good}),
        "open": finding("open", status="fix-proposed"),
        "edited": finding("edited", status="resolved", proposed_fix={"diff": good + "+y\n"}),
        "old": finding("old", status="resolved", proposed_fix={"diff": good}),
    }
    chain = [
        {"finding_id": "ok", "diff_sha256": review.diff_sha256(good)},
        {"finding_id": "open", "diff_sha256": "x"},
        {"finding_id": "edited", "diff_sha256": review.diff_sha256(good)},
        "old",
        {"finding_id": "gone", "diff_sha256": "x"},
    ]

    assert review.unmet_prerequisites(chain, by_id) == [
        {"finding_id": "open", "reason": "unresolved"},
        {"finding_id": "edited", "reason": "stale"},
        {"finding_id": "old", "reason": "unverifiable"},
        {"finding_id": "gone", "reason": "missing"},
    ]


def test_the_diff_hash_is_the_agents():
    """remediation-agent's _diff_sha256: sha256 of the UTF-8 diff text."""
    import hashlib
    assert review.diff_sha256("é") == hashlib.sha256("é".encode("utf-8")).hexdigest()


# ---------- location and filters ----------

def test_a_cdk_finding_is_located_at_its_source_line():
    f = finding("a", target_type="cdk", file="cdk.out/App.template.json",
                origin={"file": "lib/network.ts", "line": 8}, line_range=[40, 52])
    assert review.location(f) == "lib/network.ts:8"


def test_location_prints_a_range_or_a_line():
    assert review.location(finding("a", line_range=[3, 9])) == "s3.tf:3-9"
    assert review.location(finding("a", line_range=[3, 3])) == "s3.tf:3"
    assert review.location(finding("a")) == "s3.tf"


def test_filters_combine():
    fs = [
        finding("a", status="fix-proposed", severity="HIGH", file="infra/s3.tf"),
        finding("b", status="fix-proposed", severity="LOW", file="infra/s3.tf"),
        finding("c", status="mapped", severity="CRITICAL", file="k8s/app.yaml"),
        finding("d", status="fix-proposed", severity="CRITICAL", file="infrastructure.tf"),
    ]
    ids = lambda kept: [f["finding_id"] for f in kept]  # noqa: E731

    assert ids(review.filter_findings(fs, {"fix-proposed"}, "high", "infra")) == ["a"]
    assert ids(review.filter_findings(fs, file="k8s/*.yaml")) == ["c"]
    assert ids(review.filter_findings(fs, min_severity="critical")) == ["c", "d"]


def test_a_file_filter_also_matches_a_cdk_source_file():
    f = finding("a", target_type="cdk", file="cdk.out/T.json", origin={"file": "lib/network.ts", "line": 1})
    assert review.matches_file(f, "lib")
