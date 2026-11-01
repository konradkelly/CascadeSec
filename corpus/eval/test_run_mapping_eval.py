"""The mapping-accuracy scorer, on made-up pairs, candidates and runs, so
these never read the real labels or reach AWS. The case that earns the file
is the single candidate: a pair whose only candidate is wrong is one the
agent cannot get right, and must be reported as the corpus's error, not the
agent's."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import run_mapping_eval as rme  # noqa: E402

A, B, C = ("CIS-AWS-1.4", "2.1.1"), ("NIST-800-53-r5", "SC-12"), ("NIST-800-53-r5", "SC-28(1)")


def ref(control, **scope):
    return {"framework": control[0], "control_id": control[1], **scope}


def pair(rule, expected, case="case-1", target_type="terraform", source="trivy"):
    return {"case": case, "source": source, "rule_id": rule, "target_type": target_type, "expected": set(expected)}


MAPPINGS = {
    "trivy:ONE-RIGHT": [ref(A)],
    "trivy:ONE-WRONG": [ref(A)],
    "trivy:TWO-ONE-RIGHT": [ref(A), ref(B)],
    "trivy:TWO-BOTH-RIGHT": [ref(B), ref(C)],
    "trivy:SCOPED": [ref(A, target_type="kubernetes")],
}


# ---------- corpus: what the candidates allow ----------

@pytest.mark.parametrize("p, kind", [
    (pair("ONE-RIGHT", [A]), rme.EVERY_RIGHT),
    (pair("ONE-WRONG", [B]), rme.NONE_RIGHT),
    (pair("TWO-ONE-RIGHT", [B]), rme.SOME_RIGHT),
    (pair("TWO-BOTH-RIGHT", [B, C]), rme.EVERY_RIGHT),
    (pair("UNMAPPED", []), rme.RIGHTLY_EMPTY),
    (pair("UNMAPPED", [A]), rme.MISSED),
])
def test_a_pair_is_classed_by_what_its_candidates_allow(p, kind):
    assert rme.classify(p, MAPPINGS) == kind


def test_a_single_wrong_candidate_is_the_corpus_error_the_agent_cannot_avoid():
    counts = rme.score_corpus([pair("ONE-WRONG", [B]), pair("ONE-RIGHT", [A])], MAPPINGS)
    assert counts[rme.NONE_RIGHT] == 1 and counts[rme.EVERY_RIGHT] == 1


def test_a_candidate_scoped_to_another_language_is_not_offered():
    """mapping-agent's candidates_for, not the raw entry: CKV_SECRET_6's
    Kubernetes control is no candidate for the same rule on Terraform."""
    assert rme.classify(pair("SCOPED", [A], target_type="terraform"), MAPPINGS) == rme.MISSED
    assert rme.classify(pair("SCOPED", [A], target_type="kubernetes"), MAPPINGS) == rme.EVERY_RIGHT


# ---------- a run: what the agent did ----------

def finding(rule, chosen=None, case="case-1", citation="", source="trivy"):
    f = {"file": f"{case}/main.tf", "source": source, "rule_id": rule, "status": "mapped" if chosen else "raw"}
    if chosen:
        f["control_mappings"] = [{**ref(chosen), "citation_span": citation}]
    return f


def test_each_finding_of_a_labelled_pair_is_scored_by_what_was_chosen():
    pairs = [pair("TWO-ONE-RIGHT", [B]), pair("ONE-RIGHT", [A]), pair("UNMAPPED", []), pair("ONE-WRONG", [B])]
    run = [finding("TWO-ONE-RIGHT", B), finding("TWO-ONE-RIGHT", A), finding("ONE-RIGHT", A),
           finding("UNMAPPED"), finding("ONE-WRONG"), finding("NOT-LABELLED", A)]
    scored = rme.score_run(pairs, MAPPINGS, run)
    assert [(s["pair"]["rule_id"], s["outcome"]) for s in scored] == [
        ("TWO-ONE-RIGHT", "right"), ("TWO-ONE-RIGHT", "wrong"), ("ONE-RIGHT", "right"),
        ("UNMAPPED", "no candidate"),
        ("ONE-WRONG", "not mapped"),        # candidates existed, and nothing was written
    ]


def test_a_finding_in_another_case_is_not_this_pairs():
    scored = rme.score_run([pair("ONE-RIGHT", [A], case="case-1")], MAPPINGS, [finding("ONE-RIGHT", A, case="case-2")])
    assert scored == []


def test_the_report_counts_choices_per_run_and_the_pairs_that_held_steady():
    pairs = [pair("TWO-ONE-RIGHT", [B]), pair("TWO-ONE-RIGHT", [B], case="case-2")]
    runs = {"run-1": [finding("TWO-ONE-RIGHT", B), finding("TWO-ONE-RIGHT", B, case="case-2")],
            "run-2": [finding("TWO-ONE-RIGHT", B), finding("TWO-ONE-RIGHT", A, case="case-2")]}
    lines = []
    result = rme.report(pairs, MAPPINGS, {}, runs, out=lines.append)
    assert (result["runs"]["run-1"]["choice_right"], result["runs"]["run-1"]["choice_total"]) == (2, 2)
    assert (result["runs"]["run-2"]["choice_right"], result["runs"]["run-2"]["choice_total"]) == (1, 2)
    assert "pairs answered the same way in every run: 1/2 = 50.0%" in "\n".join(lines)


def test_no_runs_reports_the_corpus_alone():
    lines = []
    result = rme.report([pair("ONE-WRONG", [B])], MAPPINGS, {}, {}, out=lines.append)
    assert result["runs"] == {}
    assert "the agent cannot be right on       1/1 = 100.0%" in "\n".join(lines)


# ---------- citations ----------

TEXT = "Every S3 bucket should have default server-side encryption enabled so objects are encrypted at rest."


@pytest.mark.parametrize("citation, verdict", [
    ("default server-side encryption enabled", "verbatim"),
    ('"default  server-side\nencryption enabled"', "verbatim"),         # quotes and whitespace aside
    ("Default Server-Side Encryption Enabled", "reworded"),
    ("default serverside encryption enabled", "reworded"),
    ("encryption should be enabled by default", "not in the text"),
    ("", "not in the text"),
])
def test_a_citation_is_verbatim_only_if_the_text_has_it(citation, verdict):
    assert rme.citation_verdict(citation, TEXT)[0] == verdict


def test_a_citation_of_fifteen_words_is_over_the_limit():
    fourteen = " ".join(TEXT.split()[:14])
    assert rme.citation_verdict(fourteen, TEXT) == ("verbatim", True)
    assert rme.citation_verdict(" ".join(TEXT.split()[:15]), TEXT) == ("verbatim", False)


def test_every_mapped_finding_has_its_citation_checked_labelled_or_not():
    texts = {A: TEXT}
    cited = rme.citations([finding("ANY", A, citation="objects are encrypted at rest"), finding("RAW")], texts)
    assert [(v, short) for v, short, _ in cited] == [("verbatim", True)]


# ---------- reading the cases and the runs ----------

def test_a_cases_target_type_comes_from_its_files(tmp_path):
    case = tmp_path / "k8s-case"
    case.mkdir()
    (case / "manifest.yaml").write_text("kind: Pod\n")
    (case / "expected.json").write_text(json.dumps({"expected": [
        {"source": "trivy", "rule_id": "KSV-0001", "expected_controls": [ref(A)]}]}))
    assert rme.load_pairs(tmp_path) == [{"case": "k8s-case", "source": "trivy", "rule_id": "KSV-0001",
                                         "target_type": "kubernetes", "expected": {A}}]


def test_every_page_of_a_run_is_read():
    class Table:
        def __init__(self):
            self.pages = [{"Items": [1, 2], "LastEvaluatedKey": "k"}, {"Items": [3]}]

        def query(self, **kwargs):
            assert kwargs["ExpressionAttributeValues"][":pk"] == "PR#eval-map-1"
            return self.pages.pop(0)
    assert rme.findings_of("eval-map-1", Table()) == [1, 2, 3]


def test_every_eval_case_mixes_no_target_types():
    """load_pairs reads one target type per case, which the real cases
    must allow. Reads the cases' files, not their labels."""
    for case in rme.CASES.iterdir():
        types = {rme.CASE_FILE_TARGET_TYPES[p.name] for p in case.iterdir() if p.name in rme.CASE_FILE_TARGET_TYPES}
        assert len(types) <= 1, case.name
