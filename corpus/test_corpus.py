"""Integrity checks for the control corpus and the eval labels.

These are data tests, not code tests. Nothing here imports a Lambda or
touches AWS; they read the files in this directory and assert the things
the pipeline assumes about them at runtime.

The one that earns the file: **every (framework, control_id) in
rule_mappings.json must resolve to a control that exists.** mapping-agent
looks a reference up with `_FRAMEWORK_FILES[framework]` and
`next(c for c in ... if c["control_id"] == control_id)` -- neither guarded,
and neither inside a per-finding try/except. So a typo in this directory
does not mis-map one finding, it raises KeyError or StopIteration and takes
the whole MapToControls stage down with the pipeline execution behind it.
Catching that here costs nothing and catches it at commit time.

Run from anywhere: paths are relative to this file.
"""

import ast
import json
import pathlib
import re

import pytest

CORPUS = pathlib.Path(__file__).parent
FRAMEWORKS = sorted((CORPUS / "frameworks").glob("*.json"))
EVAL_CASES = sorted(p for p in (CORPUS / "eval" / "cases").iterdir() if p.is_dir())

# What a finding's `source` may be. Both scanners, and nothing else: an
# eval label naming a third would be a typo, not a new tool.
KNOWN_SOURCES = {"trivy", "checkov"}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _framework_index():
    """{framework_name: {control_id, ...}}, keyed by each file's own
    declaration rather than its filename."""
    index = {}
    for path in FRAMEWORKS:
        data = _load(path)
        index[data["framework"]] = {c["control_id"] for c in data["controls"]}
    return index


def _mappings():
    return _load(CORPUS / "rule_mappings.json")["mappings"]


# ---------- the framework files ----------

@pytest.mark.parametrize("path", FRAMEWORKS, ids=lambda p: p.name)
def test_a_framework_file_has_the_shape_mapping_agent_reads(path):
    data = _load(path)
    assert data["framework"], "a framework must name itself; the name is the mapping key"
    assert data["controls"], "a framework with no controls can never be cited"
    for control in data["controls"]:
        # mapping-agent puts title and text in the prompt and the citation
        # is quoted from text, so an empty one is an uncitable candidate.
        for field in ("control_id", "title", "text"):
            assert control.get(field), f"{path.name}: {control.get('control_id')!r} has no {field}"


@pytest.mark.parametrize("path", FRAMEWORKS, ids=lambda p: p.name)
def test_control_ids_are_unique_within_a_framework(path):
    ids = [c["control_id"] for c in _load(path)["controls"]]

    assert len(ids) == len(set(ids)), f"{path.name}: duplicate control_id"


def test_no_two_framework_files_claim_the_same_framework_name():
    names = [_load(p)["framework"] for p in FRAMEWORKS]

    assert len(names) == len(set(names))


# ---------- the mappings ----------

def test_every_mapping_reference_resolves_to_a_real_control():
    """The test this file exists for. An unresolvable reference is not a
    bad mapping, it is a crash: mapping-agent indexes the framework and
    then `next()`s the control, both unguarded, so the whole run dies on
    the first finding that reaches it."""
    index = _framework_index()
    broken = []
    for key, refs in _mappings().items():
        for ref in refs:
            framework, control_id = ref["framework"], ref["control_id"]
            if framework not in index:
                broken.append(f"{key} -> unknown framework {framework!r}")
            elif control_id not in index[framework]:
                broken.append(f"{key} -> {framework} has no control {control_id!r}")

    assert not broken, "unresolvable mapping(s):\n  " + "\n  ".join(broken)


def test_every_mapping_key_is_a_source_and_a_rule_id():
    """`source:rule_id`, because that is what mapping-agent builds to look
    a finding up. A key missing its prefix silently matches nothing."""
    bad = []
    for key in _mappings():
        source, sep, rule_id = key.partition(":")
        if not sep or source not in KNOWN_SOURCES or not rule_id:
            bad.append(key)

    assert not bad, f"keys that are not <source>:<rule_id> with source in {KNOWN_SOURCES}: {bad}"


def test_a_mapping_offers_no_duplicate_candidates():
    """Two identical candidates would show the model the same control
    twice and make one of them unpickable for no reason."""
    dupes = {
        key: refs for key, refs in _mappings().items()
        if len({(r["framework"], r["control_id"]) for r in refs}) != len(refs)
    }

    assert not dupes, f"duplicate candidates: {dupes}"


def test_the_handlers_framework_map_matches_the_files_on_disk():
    """mapping-agent holds framework -> filename in code while the files
    live here, so the two can drift apart in either direction: a framework
    added here and not there raises KeyError at runtime; one listed there
    and missing here fails on the S3 read. Parsed out of the source rather
    than imported, since importing the handler would pull in boto3 and
    anthropic for a data check."""
    source = (CORPUS.parent / "lambda" / "mapping-agent" / "handler.py").read_text(encoding="utf-8")
    match = re.search(r"^_FRAMEWORK_FILES = (\{.*?^\})", source, re.S | re.M)
    assert match, "could not find _FRAMEWORK_FILES in mapping-agent/handler.py"
    declared = ast.literal_eval(match.group(1))

    on_disk = {_load(p)["framework"]: p.name for p in FRAMEWORKS}

    assert declared == on_disk


# ---------- the eval labels ----------

@pytest.mark.parametrize("case", EVAL_CASES, ids=lambda p: p.name)
def test_an_eval_case_has_a_sample_and_a_label(case):
    expected = case / "expected.json"
    assert expected.exists(), f"{case.name}: no expected.json"
    samples = [p for p in case.iterdir() if p.name != "expected.json"]
    assert samples, f"{case.name}: nothing to scan"


@pytest.mark.parametrize("case", EVAL_CASES, ids=lambda p: p.name)
def test_an_eval_label_names_a_known_source_and_a_rule(case):
    """run_eval.py compares (source, rule_id) pairs, so a label with a
    misspelled source can never match and would read as a scanner gap
    rather than as the typo it is."""
    data = _load(case / "expected.json")
    assert data.get("description"), f"{case.name}: no description"
    assert data.get("category"), f"{case.name}: no category"
    for entry in data["expected"]:
        assert entry["source"] in KNOWN_SOURCES, f"{case.name}: source {entry['source']!r}"
        assert entry.get("rule_id"), f"{case.name}: an expectation with no rule_id"


def test_a_case_expecting_nothing_says_why():
    """An empty `expected` is a deliberate statement -- a clean control, or
    a gap neither tool covers -- and is indistinguishable from an unfinished
    case unless the note says which."""
    silent = [
        case.name for case in EVAL_CASES
        if not _load(case / "expected.json")["expected"]
        and not _load(case / "expected.json").get("note")
        and _load(case / "expected.json")["category"] != "clean-control"
    ]

    assert not silent, f"cases expecting nothing with no note explaining why: {silent}"
