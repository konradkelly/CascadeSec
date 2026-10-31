"""SARIF output (sarif-spec): every document the writer emits validates
against the SARIF 2.1.0 schema, vendored in tests/data from OASIS (errata01),
and keeps the rules GitHub Code Scanning applies to an upload. Docker is
faked at the subprocess boundary; git is real. A recorded upload to the
testbed is in sarif-spec §5."""

import ast
import io
import json
import re
from pathlib import Path

import jsonschema
import pytest

from cascadesec import baseline, sarif
from cascadesec import main as cli
from conftest import Scanner

REPO = Path(__file__).resolve().parents[2]
SCHEMA =json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))

BUCKET = {"source": "trivy", "rule_id": "AWS-0086", "title": "S3 Access block should block public ACL",
          "description": "S3 buckets should block public ACLs on buckets and any objects they contain.",
          "severity": "HIGH", "file": "s3.tf", "line_range": [3, 9], "resource": "aws_s3_bucket.data",
          "target_type": "terraform", "fingerprint": "a1b2c3d4e5f60718", "finding_id": "0011223344556677",
          "candidates": [{"framework": "CIS-AWS-1.4", "control_id": "2.1.5", "title": "Block public access"}]}
CHECKOV = {"source": "checkov", "rule_id": "CKV_AWS_18", "title": "Ensure the S3 bucket has access logging enabled",
           "description": "", "severity": "UNKNOWN", "file": "s3.tf", "line_range": [3, 9],
           "resource": "aws_s3_bucket.data", "target_type": "terraform", "fingerprint": "f0e1d2c3b4a59687",
           "finding_id": "8899aabbccddeeff", "candidates": [], "raw_reason": "hygiene"}
KICS = {"source": "kics", "rule_id": "8d29754a-2a18-460d-a1ba-9509f8d359da", "title": "IAM Access Analyzer Not Enabled",
        "description": "IAM Access Analyzer should be enabled", "severity": "LOW",
        "file": "cloudformation/events.yaml", "line_range": [9, 9], "resource": "n/a",
        "target_type": "cloudformation", "fingerprint": "6239b4b146967117", "finding_id": "4420d6539a74d847",
        "candidates": [], "raw_reason": "unreviewed"}
WHOLE_FILE = {**KICS, "rule_id": "whole", "line_range": [None, None], "fingerprint": "1111111111111111"}


def summary(findings=(), errors=(), apps=(), skipped=(), baseline_file=None):
    return {"findings": list(findings), "scan_errors": list(errors), "unscanned_apps": list(apps),
            "skipped_apps": list(skipped), "scanner_image": "img@sha256:abc", "baseline": baseline_file}


def valid(document):
    errors = sorted(jsonschema.Draft4Validator(SCHEMA).iter_errors(document), key=str)
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors[:5]]
    return document


def results(document):
    return document["runs"][0]["results"]


def rules(document):
    return {r["id"]: r for r in document["runs"][0]["tool"]["driver"]["rules"]}


# ---------- the document ----------

@pytest.mark.parametrize("scan", [
    summary(),
    summary([BUCKET, CHECKOV, KICS, WHOLE_FILE]),
    summary([BUCKET], errors=["broken.tf"], apps=[{"path": "cdk", "kind": "cdk", "reason": "not run"}],
            skipped=[{"path": "lab", "kind": "pulumi", "reason": "throwaway", "source": ".cascadesec.toml"}]),
], ids=["empty", "findings", "incomplete"])
def test_every_document_is_valid_sarif(scan):
    document = valid(sarif.document(scan, [CHECKOV], "0.1.0", "infra/"))
    assert document["version"] == "2.1.0"
    driver = document["runs"][0]["tool"]["driver"]
    assert (driver["name"], driver["version"]) == ("CascadeSec", "0.1.0")
    assert driver["properties"]["scannerImage"] == "img@sha256:abc"


def test_one_rule_per_tool_and_rule_prefixed_because_ids_collide_across_tools():
    document = sarif.document(summary([BUCKET, {**BUCKET, "line_range": [20, 25], "fingerprint": "2" * 16},
                                       CHECKOV, KICS]), [], "0.1.0")
    assert sorted(rules(document)) == ["checkov:CKV_AWS_18", "kics:8d29754a-2a18-460d-a1ba-9509f8d359da",
                                       "trivy:AWS-0086"]
    for result in results(document):
        assert rules(document)[result["ruleId"]] is document["runs"][0]["tool"]["driver"]["rules"][
            result["ruleIndex"]]


def test_security_severity_sits_inside_githubs_band_for_each_severity():
    # GitHub: over 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
    bands = {"CRITICAL": (9.0, 10.0), "HIGH": (7.0, 8.9), "MEDIUM": (4.0, 6.9), "LOW": (0.1, 3.9)}
    for severity, (low, high) in bands.items():
        document = sarif.document(summary([{**BUCKET, "severity": severity}]), [], "0.1.0")
        score = float(rules(document)["trivy:AWS-0086"]["properties"]["security-severity"])
        assert low < score <= high if severity == "CRITICAL" else low <= score <= high
    # No severity from the tool, none invented: GitHub ranks it by level.
    unrated = rules(sarif.document(summary([CHECKOV]), [], "0.1.0"))["checkov:CKV_AWS_18"]
    assert "security-severity" not in unrated["properties"]


def test_level_follows_severity():
    levels = {s: results(sarif.document(summary([{**BUCKET, "severity": s}]), [], "0.1.0"))[0]["level"]
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    assert levels == {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note",
                      "UNKNOWN": "note"}


def test_a_rule_has_the_text_github_requires_even_when_the_tool_gave_none():
    rule = rules(sarif.document(summary([CHECKOV]), [], "0.1.0"))["checkov:CKV_AWS_18"]
    # checkov reports a name and no description; GitHub rejects an empty one.
    assert rule["fullDescription"]["text"] == CHECKOV["title"]
    assert rule["help"]["text"].startswith(CHECKOV["title"])
    assert "hygiene rule" in rule["help"]["text"]

    long = {**BUCKET, "description": "x" * 5000}
    rule = rules(sarif.document(summary([long]), [], "0.1.0"))["trivy:AWS-0086"]
    assert len(rule["fullDescription"]["text"]) == sarif.MAX_TEXT


def test_candidate_controls_are_tags_and_help_and_say_they_are_candidates():
    rule = rules(sarif.document(summary([BUCKET]), [], "0.1.0"))["trivy:AWS-0086"]
    assert rule["properties"]["tags"] == ["security", "terraform", "CIS-AWS-1.4/2.1.5"]
    assert "CIS-AWS-1.4/2.1.5: Block public access" in rule["help"]["text"]
    assert "a local scan does not choose" in rule["help"]["text"]
    (result,) = results(sarif.document(summary([BUCKET]), [], "0.1.0"))
    assert result["properties"]["candidate_controls"] == ["CIS-AWS-1.4/2.1.5"]


def test_a_rule_never_carries_more_tags_than_github_accepts():
    many = {**BUCKET, "candidates": [{"framework": "NIST-800-53-r5", "control_id": f"AC-{i}"} for i in range(40)]}
    rule = rules(sarif.document(summary([many]), [], "0.1.0"))["trivy:AWS-0086"]
    assert len(rule["properties"]["tags"]) == sarif.MAX_TAGS
    assert rule["properties"]["tags"][:2] == ["security", "terraform"]


def test_message_names_the_resource_unless_the_tool_named_none():
    positional = {**BUCKET, "rule_id": "AWS-0096", "resource": "cloudformation/events.yaml:10-15"}
    document = sarif.document(summary([BUCKET, KICS, positional]), [], "0.1.0")
    by_rule = {r["ruleId"]: r["message"]["text"] for r in results(document)}
    assert by_rule["trivy:AWS-0086"] == "S3 Access block should block public ACL (aws_s3_bucket.data)"
    assert by_rule["kics:8d29754a-2a18-460d-a1ba-9509f8d359da"] == "IAM Access Analyzer Not Enabled"
    # A position, which the location already gives and which moves with the lines.
    assert by_rule["trivy:AWS-0096"] == BUCKET["title"]


def test_what_names_no_resource_is_what_the_scanners_fingerprint_says():
    source = (REPO / "lambda" / "iac-scanner" / "handler.py").read_text(encoding="utf-8")
    pattern = re.search(r'^POSITIONAL_RESOURCE_RE = re\.compile\((r".*?")\)$', source, re.M).group(1)
    assert ast.literal_eval(pattern) == sarif.POSITIONAL_RESOURCE_RE.pattern
    placeholders = re.search(r"^PLACEHOLDER_RESOURCES = (\{.*?\})$", source, re.M).group(1)
    assert ast.literal_eval(placeholders) == sarif.PLACEHOLDER_RESOURCES


def test_locations_are_from_the_repository_root_and_a_whole_file_finding_has_no_region():
    spaced = {**BUCKET, "file": "my stacks/s3#1.tf"}
    document = valid(sarif.document(summary([BUCKET, WHOLE_FILE, spaced]), [], "0.1.0", "infra/"))
    locations = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]:
                 r["locations"][0]["physicalLocation"].get("region") for r in results(document)}
    assert locations["infra/s3.tf"] == {"startLine": 3, "endLine": 9}
    assert locations["infra/cloudformation/events.yaml"] is None
    assert "infra/my%20stacks/s3%231.tf" in locations


def test_fingerprints_survive_a_line_inserted_above_and_tell_apart_two_that_share_one():
    # One rule, one resource, two lines of it: the documented shared fingerprint.
    twin = {**BUCKET, "line_range": [12, 14], "finding_id": "77" * 8}
    before = sarif.document(summary([BUCKET, twin, KICS]), [], "0.1.0")
    shifted = [{**f, "line_range": [f["line_range"][0] + 1, f["line_range"][1] + 1]} for f in (BUCKET, twin, KICS)]
    after = sarif.document(summary(shifted), [], "0.1.0")

    keys = [r["partialFingerprints"] for r in results(before)]
    assert keys == [r["partialFingerprints"] for r in results(after)]
    hashes = sorted(k["primaryLocationLineHash"] for k in keys)
    assert hashes == ["6239b4b146967117:1", "a1b2c3d4e5f60718:1", "a1b2c3d4e5f60718:2"]
    assert all(k["cascadesec/v1"] == k["primaryLocationLineHash"].split(":")[0] for k in keys)


def test_baselined_findings_are_emitted_as_suppressed_not_left_out():
    document = valid(sarif.document(summary([BUCKET], baseline_file=".cascadesec-baseline.json"),
                                    [CHECKOV], "0.1.0"))
    by_rule = {r["ruleId"]: r for r in results(document)}
    assert "suppressions" not in by_rule["trivy:AWS-0086"]
    assert "baselineState" not in by_rule["trivy:AWS-0086"]
    accepted = by_rule["checkov:CKV_AWS_18"]
    assert accepted["suppressions"] == [{"kind": "external", "status": "accepted",
                                         "justification": "in .cascadesec-baseline.json"}]
    assert accepted["baselineState"] == "unchanged"


def test_a_scan_that_did_not_happen_is_not_a_clean_run():
    incomplete = sarif.document(summary(errors=["broken.tf"],
                                        apps=[{"path": ".", "kind": "cdk", "reason": "not run locally"}]),
                                [], "0.1.0", "infra/")
    (invocation,) = incomplete["runs"][0]["invocations"]
    assert invocation["executionSuccessful"] is False
    notes = invocation["toolExecutionNotifications"]
    assert [(n["level"], n["descriptor"]["id"]) for n in notes] == [("error", "scan-error"),
                                                                     ("error", "app-not-run")]
    assert [n["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for n in notes] == [
        "infra/broken.tf", "infra"]

    skipped = sarif.document(summary(skipped=[{"path": "lab", "kind": "pulumi", "reason": "throwaway",
                                               "source": ".cascadesec.toml"}]), [], "0.1.0")
    (invocation,) = skipped["runs"][0]["invocations"]
    assert invocation["executionSuccessful"] is True
    assert [n["level"] for n in invocation["toolExecutionNotifications"]] == ["note"]
    assert "throwaway" in invocation["toolExecutionNotifications"][0]["message"]["text"]


def test_only_scanner_and_corpus_text_reaches_the_document():
    # Fields a remote record carries; none of them is the scanner's or the corpus's.
    prose = {**BUCKET, "rationale": "MODEL-RATIONALE", "assumptions": ["MODEL-ASSUMPTION"],
             "proposed_fix": {"explanation": "MODEL-EXPLANATION"}}
    text = sarif.dumps(sarif.document(summary([prose]), [], "0.1.0"))
    assert "MODEL-" not in text


def test_over_limits_names_what_github_would_reject(monkeypatch):
    document = sarif.document(summary([BUCKET, CHECKOV]), [], "0.1.0")
    assert sarif.over_limits(document, sarif.dumps(document)) == []
    monkeypatch.setattr(sarif, "MAX_RESULTS", 1)
    monkeypatch.setattr(sarif, "MAX_GZIP_BYTES", 10)
    problems = sarif.over_limits(document, sarif.dumps(document))
    assert problems[0] == "2 results, over the 1 a run may hold"
    assert "gzipped, over the 10 MB upload limit" in problems[1]


# ---------- cascadesec scan --format sarif ----------

def run(argv, cwd, scanner):
    out = io.StringIO()
    code = cli.main(argv, stdout=out, env={"CASCADESEC_SCANNER_IMAGE": "img:1"}, cwd=cwd, run=scanner)
    return code, out.getvalue()


def test_scan_writes_sarif_after_the_command_and_keeps_its_exit_code(git_repo):
    infra = git_repo.path / "infra"
    infra.mkdir()
    code, out = run(["scan", str(infra), "--format", "sarif"], git_repo.path, Scanner(now=[BUCKET, CHECKOV]))
    document = valid(json.loads(out))
    # The scan's paths are from infra/; a SARIF consumer reads them from the root.
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results(document)}
    assert uris == {"infra/s3.tf"}
    assert code == 1            # a HIGH finding, at the default --fail-on high

    code, _ = run(["scan", str(infra), "--format", "sarif", "--fail-on", "none"], git_repo.path,
                  Scanner(now=[BUCKET]))
    assert code == 0


def test_output_holds_the_same_document(git_repo):
    target = git_repo.path / "out.sarif"
    _, out = run(["scan", str(git_repo.path), "--format", "sarif", "--output", str(target)], git_repo.path,
                 Scanner(now=[BUCKET]))
    assert target.read_text(encoding="utf-8") == out
    assert results(json.loads(out))[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "s3.tf"


def test_baselined_findings_are_in_the_sarif_but_not_in_the_verdict(git_repo):
    baseline.write(git_repo.path / baseline.FILE, baseline.entries_for([BUCKET]), "img:1")
    code, out = run(["scan", str(git_repo.path), "--format", "sarif"], git_repo.path,
                    Scanner(now=[BUCKET, CHECKOV]))
    by_rule = {r["ruleId"]: r for r in results(valid(json.loads(out)))}
    assert by_rule["trivy:AWS-0086"]["suppressions"][0]["justification"].endswith(baseline.FILE)
    assert "suppressions" not in by_rule["checkov:CKV_AWS_18"]
    assert code == 0            # the HIGH one is baselined; checkov's has no severity


def test_outside_a_repository_paths_stay_relative_to_the_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    monkeypatch.setattr("cascadesec.scan.shutil.which", lambda name: "/usr/bin/docker")
    _, out = run(["scan", str(tmp_path), "--format", "sarif"], tmp_path, Scanner(now=[BUCKET]))
    assert results(json.loads(out))[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "s3.tf"


def test_a_file_github_would_reject_is_not_written(git_repo, monkeypatch, capsys):
    monkeypatch.setattr(sarif, "MAX_RESULTS", 1)
    target = git_repo.path / "out.sarif"
    code, out = run(["scan", str(git_repo.path), "--format", "sarif", "--output", str(target)], git_repo.path,
                    Scanner(now=[BUCKET, CHECKOV]))
    assert (code, out, target.exists()) == (2, "", False)
    assert "2 results, over the 1 a run may hold" in capsys.readouterr().err


def test_sarif_is_only_for_scan(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_:
        cli.main(["findings", "gh-1-2", "--format", "sarif"], stdout=io.StringIO(), env={}, cwd=tmp_path)
    assert exit_.value.code == 2
    assert "--format sarif is for scan" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["--format", "json", "version"], ["version", "--format", "json"],
                                  ["--format", "table", "version", "--format", "json"]])
def test_format_is_taken_before_or_after_the_command(argv, tmp_path):
    out = io.StringIO()
    assert cli.main(argv, stdout=out, env={}, cwd=tmp_path) == 0
    assert json.loads(out.getvalue())["cli"]


def test_format_given_only_before_the_command_is_kept(tmp_path):
    out = io.StringIO()
    cli.main(["--format", "table", "version"], stdout=out, env={}, cwd=tmp_path)
    assert out.getvalue().startswith("cascadesec")
