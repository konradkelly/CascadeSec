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

# What a finding's `source` may be. The three scanners, and nothing else:
# an eval label naming a fourth would be a typo, not a new tool. kics
# joined 2026-09-23 for ARM and Bicep, where Trivy's adapter cannot
# satisfy its own checks (docs/trivy-azure-arm-adapter-gap.md).
KNOWN_SOURCES = {"trivy", "checkov", "kics"}

# What a candidate's optional `target_type` scope may say. Must stay in step
# with iac-scanner's SUFFIX_TARGET_TYPES and the types the tools report
# (multi-iac-spec §3.1); the ones not yet admitted to the scanner are listed
# so a mapping can be written the day a language lands.
KNOWN_TARGET_TYPES = {"terraform", "opentofu", "kubernetes", "helm",
                      "cloudformation", "arm", "bicep", "npm", "dockerfile"}


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
    bad mapping, it is a fault: mapping-agent indexes the framework and
    then `next()`s the control, both unguarded, and the per-finding
    isolation turns that into an error_count rather than a crash -- which
    means it would recur silently on every scan that hit the rule."""
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


def test_a_scoped_candidate_names_a_target_type_that_can_exist():
    """A candidate may carry `target_type` to scope it to one language. A
    typo there is the worst kind of bug this file can hold: the candidate is
    silently never offered, the finding stays `raw`, and nothing anywhere
    reports an error -- it looks exactly like a rule nobody mapped."""
    bad = [
        f"{key} -> {ref['framework']}:{ref['control_id']} scoped to {ref['target_type']!r}"
        for key, refs in _mappings().items()
        for ref in refs
        if "target_type" in ref and ref["target_type"] not in KNOWN_TARGET_TYPES
    ]

    assert not bad, "candidate(s) scoped to an unknown target_type:\n  " + "\n  ".join(bad)


def test_a_rule_does_not_scope_every_candidate_away():
    """A rule whose candidates are all scoped to one language offers nothing
    at all for the others, which is the same as being unmapped there -- fine
    when deliberate, but it should be visible rather than an accident of
    editing. Today every such rule keeps at least one universal candidate."""
    stranded = [
        key for key, refs in _mappings().items()
        if refs and all("target_type" in r for r in refs)
    ]

    assert not stranded, (
        "rule(s) with no universal candidate; intended? then note it here: "
        f"{stranded}"
    )


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


def test_every_copy_of_the_snapshot_predicate_says_the_same_thing():
    """What the scanner opens is declared in more than one file.

    SNAPSHOT_SUFFIXES and ARM_SCHEMA_RE live in iac-scanner/handler.py,
    scripts/scan.py, eval/run_eval.py and external/run_external.py, and the
    ARM predicate additionally in context-agent/handler.py, because there is
    no shared package to put them in and the scanner is a container image
    built from its own directory. Each says "keep the copies aligned" in a
    comment; this is what makes that true rather than aspirational.

    A drifted ARM predicate is the worse of the two failures, and it is
    invisible from either end: the uploader stops sending a template the
    scanner would have scanned, so the file is simply absent from the
    findings -- no error, no scan_error, nothing to notice.

    Parsed out of the sources rather than imported, since importing the
    handlers would pull boto3 and anthropic into a data check.
    """
    suffix_copies, schema_copies, cfn_copies = {}, {}, {}
    for rel in ("lambda/iac-scanner/handler.py",
                "scripts/scan.py",
                "corpus/eval/run_eval.py",
                "corpus/external/run_external.py",
                "lambda/context-agent/handler.py",
                # v3: the GitHub App's uploader. It keeps what the scanner
                # opens out of a repository tarball, so a drift here loses
                # files from every PR scan with nothing to say so.
                "lambda/github-gateway/handler.py"):
        source = (CORPUS.parent / rel).read_text(encoding="utf-8")
        schema = re.search(r"^ARM_SCHEMA_RE = re\.compile\((r'[^']*')\)$", source, re.M)
        assert schema, f"{rel}: no ARM_SCHEMA_RE"
        schema_copies[rel] = schema.group(1)
        # CloudFormation's marker, added 2026-09-23. It matters more than
        # ARM's did: the two languages share the .json suffix, so a drifted
        # copy here does not merely lose a file, it can hand a template to
        # the wrong language's structural guard.
        cfn = re.search(r"^CFN_MARKER_RE = re\.compile\((r'[^']*')\)$", source, re.M)
        assert cfn, f"{rel}: no CFN_MARKER_RE"
        cfn_copies[rel] = cfn.group(1)
        # context-agent reads more than the scanner opens -- its list is
        # CONTEXT_SUFFIXES and is allowed to differ -- but "is this an ARM
        # template" is the same question everywhere and must not.
        suffixes = re.search(r"^SNAPSHOT_SUFFIXES = (\(.*?\))$", source, re.S | re.M)
        if suffixes:
            suffix_copies[rel] = ast.literal_eval(suffixes.group(1))

    assert len(suffix_copies) == 5, sorted(suffix_copies)

    assert len(set(suffix_copies.values())) == 1, (
        "SNAPSHOT_SUFFIXES has drifted:\n  "
        + "\n  ".join(f"{rel}: {value}" for rel, value in suffix_copies.items())
    )
    assert len(set(schema_copies.values())) == 1, (
        "ARM_SCHEMA_RE has drifted:\n  "
        + "\n  ".join(f"{rel}: {value}" for rel, value in schema_copies.items())
    )
    assert len(set(cfn_copies.values())) == 1, (
        "CFN_MARKER_RE has drifted:\n  "
        + "\n  ".join(f"{rel}: {value}" for rel, value in cfn_copies.items())
    )


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


def test_every_case_file_declares_the_target_type_it_should_scan_as():
    """run_eval.py checks each finding's target_type against the language its
    file's name declares, and refuses to run on a file name it has no entry
    for. That refusal only happens against AWS; this makes the same check in
    CI, so a new case cannot reach the eval with its target unchecked.

    Parsed out of the source rather than imported, like the snapshot
    predicate above, so this data check does not pull in boto3.
    """
    source = (CORPUS / "eval" / "run_eval.py").read_text(encoding="utf-8")
    table = re.search(r"^CASE_FILE_TARGET_TYPES = (\{.*?\n\})$", source, re.S | re.M)
    assert table, "run_eval.py: no CASE_FILE_TARGET_TYPES"
    declared = ast.literal_eval(table.group(1))

    assert set(declared.values()) <= KNOWN_TARGET_TYPES
    for case in EVAL_CASES:
        for path in case.iterdir():
            if path.name == "expected.json":
                continue
            assert path.name in declared, (
                f"{case.name}/{path.name}: add it to CASE_FILE_TARGET_TYPES in run_eval.py")


def test_both_uploaders_skip_the_same_directories_including_cdk_out():
    """scan.py and run_external.py each walk a checkout and each say their
    SKIP_DIRS must match the other's; this makes that true. cdk.out is
    asserted by name because leaving it out is a scope decision rather than
    noise reduction (multi-iac-spec §7.1): CDK's synthesized templates are
    CloudFormation the scanner admits by content, so dropping it from either
    list would have generated templates scanned and remediated as if someone
    wrote them."""
    copies = {}
    for rel in ("scripts/scan.py", "corpus/external/run_external.py",
                "lambda/github-gateway/handler.py"):
        source = (CORPUS.parent / rel).read_text(encoding="utf-8")
        found = re.search(r"^SKIP_DIRS = (\{.*?\})$", source, re.S | re.M)
        assert found, f"{rel}: no SKIP_DIRS"
        copies[rel] = ast.literal_eval(found.group(1))

    assert len({frozenset(v) for v in copies.values()}) == 1, copies
    assert all("cdk.out" in v for v in copies.values())


def test_the_receiver_and_the_gateway_agree_on_the_check_run():
    """github-gateway names the check run and its Draft fixes button;
    webhook-receiver recognises a click by the same two strings. A drift
    would not fail anything visibly: the button would be on the PR, and a
    click would be ignored as some other app's check run."""
    values = {}
    for rel in ("lambda/webhook-receiver/handler.py", "lambda/github-gateway/handler.py"):
        source = (CORPUS.parent / rel).read_text(encoding="utf-8")
        values[rel] = tuple(
            re.search(rf'^{name} = "([^"]+)"$', source, re.M).group(1)
            for name in ("CHECK_NAME", "DRAFT_FIXES_ACTION")
        )
    assert len(set(values.values())) == 1, values
