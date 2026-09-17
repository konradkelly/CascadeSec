"""Tests for iac-scanner's handler.

No AWS calls are made -- S3, DynamoDB, and both scanner subprocesses are
mocked. The focus is the distinction the scanner owes its callers: a scan
that ran and found nothing, versus a scan that did not run or could not read
its input. Those used to be the same empty list, and remediation-agent reads
an empty list as proof that a fix worked.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import handler

FIXTURES = Path(__file__).parent / "fixtures"

WORK_DIR = "/tmp/scan-abc123"

# Captured verbatim from trivy 0.74.0 on 2026-09-12, scanning a directory of
# one good file and one with an unclosed block. Trivy reports the parse
# failure on stderr, once per module that loads the file (twice here for the
# root module), and carries on: stdout is still a full JSON report with the
# good file's findings in it.
TRIVY_PARSE_FAILURE_STDERR = (
    '2026-09-12T16:44:07-07:00\tERROR\t[terraform parser] Error parsing file\t'
    'module="root" file_path="bad.tf" cause="resource \\"aws_s3_bucket\\" \\"b\\" {" '
    'err="bad.tf:1,30-31: Unclosed configuration block; There is no closing brace '
    'for this block before the end of the file. This may be caused by incorrect '
    'brace nesting elsewhere in this file."\n'
) * 2

# One misconfiguration as Trivy emits it (Code and References trimmed).
TRIVY_SQS_MISCONF = {
    "Type": "Terraform Security Check",
    "ID": "AWS-0096",
    "Title": "Unencrypted SQS queue.",
    "Severity": "HIGH",
    "Status": "FAIL",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws-0096",
    "CauseMetadata": {"Resource": "aws_sqs_queue.plain", "Provider": "AWS", "Service": "sqs",
                      "StartLine": 1, "EndLine": 3},
}


def _trivy_report(results=()):
    """Trivy's JSON report shape: Results is absent when nothing was found,
    and a scanned directory also gets a Result for "." with no findings."""
    report = {"SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem"}
    if results:
        report["Results"] = [{"Target": ".", "Class": "config", "Type": "terraform"}] + [
            {"Target": target, "Class": "config", "Type": "terraform", "Misconfigurations": list(misconfs)}
            for target, misconfs in results
        ]
    return report


def _proc(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _checkov_report(failed_checks=(), parsing_errors=()):
    """checkov's non-quiet JSON shape (Report.get_dict upstream)."""
    return {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": list(failed_checks),
            "skipped_checks": [],
            "parsing_errors": list(parsing_errors),
        },
        "summary": {"passed": 0, "failed": len(failed_checks), "skipped": 0,
                    "parsing_errors": len(parsing_errors)},
    }


# ---------- a tool that failed is not a tool that found nothing ----------

@patch.object(handler.subprocess, "run")
def test_trivy_producing_no_output_raises_rather_than_scanning_clean(mock_run):
    """The false-pass path. Trivy always emits a report object with --format
    json, so empty stdout means the binary failed -- and returning [] for that
    would tell remediation-agent the file is clean."""
    mock_run.return_value = _proc(stdout="", stderr="fork/exec: permission denied", returncode=126)

    with pytest.raises(handler.ScannerError, match="trivy produced no output"):
        handler._run_trivy(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_trivy_output_that_is_not_json_raises(mock_run):
    """A genuine crash still has to raise. Trivy never puts a parse failure
    on stdout, so unlike tfsec there is nothing to downgrade here."""
    mock_run.return_value = _proc(stdout="panic: runtime error\n", returncode=2)

    with pytest.raises(handler.ScannerError, match="unparseable"):
        handler._run_trivy(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_trivy_parse_failure_is_reported_not_raised(mock_run):
    """Against the real captured output. Raising here would be safe but wrong:
    remediation-agent turns a raised error into a retry with the finding left
    at "mapped", so an agent that drops a brace would loop -- re-drafting, re-
    failing, and costing a model call each time -- while no reviewer ever sees
    it. Reported, it becomes needs-human-only with the reason attached.

    And unlike tfsec, the other file's findings survive: Trivy skips the
    broken file rather than abandoning the scan."""
    mock_run.return_value = _proc(
        stdout=json.dumps(_trivy_report([("good.tf", [TRIVY_SQS_MISCONF])])),
        stderr=TRIVY_PARSE_FAILURE_STDERR, returncode=0,
    )

    results, parse_errors = handler._run_trivy(WORK_DIR)

    assert [(r["ID"], r["Target"]) for r in results] == [("AWS-0096", "good.tf")]
    assert parse_errors == ["bad.tf"]


@patch.object(handler.subprocess, "run")
def test_trivy_is_run_offline_with_the_projects_own_checks(mock_run):
    """The flags that make a scan reproducible and complete: the embedded
    bundle rather than a fetch, and the checks shipped in the image under
    the namespace Trivy has to be told to evaluate -- without
    --check-namespaces a check from disk loads and silently never fires."""
    mock_run.return_value = _proc(stdout=json.dumps(_trivy_report()), returncode=0)

    handler._run_trivy(WORK_DIR)

    args = mock_run.call_args.args[0]
    assert args[:3] == [handler.TRIVY_BIN, "config", WORK_DIR]
    assert "--skip-check-update" in args
    assert args[args.index("--config-check") + 1] == handler.TRIVY_CHECKS_DIR
    assert args[args.index("--check-namespaces") + 1] == "user"


@patch.object(handler.subprocess, "run")
def test_trivy_report_without_results_is_a_clean_scan_not_an_error(mock_run):
    """Trivy's genuine clean scan: a report with no Results key at all. Must
    stay distinguishable from the failures above -- if this raised, every
    clean self-check would fail."""
    mock_run.return_value = _proc(stdout=json.dumps(_trivy_report()), returncode=0)

    assert handler._run_trivy(WORK_DIR) == ([], [])


def test_trivy_findings_normalize_to_the_record_shape():
    """ID as Trivy emits it ("AWS-0096", the form rule_mappings.json is keyed
    on), the per-Result Target as the file, CauseMetadata's lines, and the
    two axes off the Result's Type and Class."""
    [finding] = handler._normalize_trivy(
        [{**TRIVY_SQS_MISCONF, "Target": "queues/main.tf", "Type": "terraform", "Class": "config"}],
        "pr-1",
    )

    assert finding["source"] == "trivy"
    assert finding["rule_id"] == "AWS-0096"
    assert finding["file"] == "queues/main.tf"
    assert finding["line_range"] == [1, 3]
    assert finding["severity"] == "HIGH"
    assert finding["target_type"] == "terraform"
    assert finding["finding_class"] == "misconfiguration"
    assert "iac_type" not in finding


# ---------- the two axes ----------
#
# docs/multi-iac-spec.md §3.1. One field could not answer both "what do I
# re-run to verify a fix" and "what kind of problem is this", and npm is
# what forced the split.

@pytest.mark.parametrize("path,expected", [
    ("main.tf", "terraform"),
    ("main.tf.json", "terraform"),
    ("terraform.tfvars", "terraform"),
    ("terraform.tfvars.json", "terraform"),
    ("main.tofu", "opentofu"),
    ("main.tofu.json", "opentofu"),
])
def test_the_suffix_decides_target_type_where_it_is_more_specific(path, expected):
    """Trivy reports .tofu as "terraform" because it is the same HCL. A
    reviewer still wants to know which file they are looking at, and a
    repository can hold both."""
    assert handler._target_type_for(path, "terraform") == expected


def test_an_unrecognised_suffix_falls_back_to_what_the_tool_said():
    assert handler._target_type_for("deploy.yaml", "kubernetes") == "kubernetes"
    assert handler._target_type_for("deploy.yaml", None) == "unknown"


def test_a_checkov_secret_is_a_secret_found_in_terraform():
    """checkov's check_type names a discipline here, not a target, so the
    target has to come from the file. This is the case that proves the two
    axes do not derive from each other."""
    report = {
        "check_type": "secrets",
        "results": {"failed_checks": [{
            "check_id": "CKV_SECRET_6", "file_path": "/terraform.tfvars",
            "file_line_range": [1, 1], "severity": "HIGH",
        }]},
    }

    [finding] = handler._normalize_checkov(report, "pr-1")

    assert finding["finding_class"] == "secret"
    assert finding["target_type"] == "terraform"


def test_a_checkov_misconfiguration_takes_its_target_from_check_type():
    report = {
        "check_type": "terraform",
        "results": {"failed_checks": [{
            "check_id": "CKV_AWS_24", "file_path": "/main.tf",
            "file_line_range": [1, 9], "severity": "HIGH",
        }]},
    }

    [finding] = handler._normalize_checkov(report, "pr-1")

    assert finding["finding_class"] == "misconfiguration"
    assert finding["target_type"] == "terraform"


def test_check_type_is_read_per_report_not_flattened():
    """checkov returns a list of reports when more than one framework had
    something to say, and check_type lives on the report. Flattening the
    failed_checks first -- which this did until 2026-09-16 -- loses which
    framework each came from."""
    report = [
        {"check_type": "terraform", "results": {"failed_checks": [
            {"check_id": "CKV_AWS_24", "file_path": "/main.tf", "file_line_range": [1, 9]}]}},
        {"check_type": "secrets", "results": {"failed_checks": [
            {"check_id": "CKV_SECRET_6", "file_path": "/terraform.tfvars", "file_line_range": [1, 1]}]}},
    ]

    by_rule = {f["rule_id"]: f for f in handler._normalize_checkov(report, "pr-1")}

    assert by_rule["CKV_AWS_24"]["finding_class"] == "misconfiguration"
    assert by_rule["CKV_SECRET_6"]["finding_class"] == "secret"


@patch.object(handler.subprocess, "run")
def test_checkov_producing_no_output_raises(mock_run):
    mock_run.return_value = _proc(stdout="", stderr="MemoryError", returncode=137)

    with pytest.raises(handler.ScannerError, match="checkov produced no output"):
        handler._run_checkov(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_checkov_producing_unparseable_output_raises(mock_run):
    mock_run.return_value = _proc(stdout="Traceback (most recent call last):\n", returncode=1)

    with pytest.raises(handler.ScannerError, match="unparseable"):
        handler._run_checkov(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_a_scan_timeout_propagates(mock_run):
    """Already the behaviour before ScannerError existed, and worth pinning:
    a timeout must not be swallowed into an empty result either."""
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=240)

    with pytest.raises(subprocess.TimeoutExpired):
        handler._run_trivy(WORK_DIR)


# ---------- snapshot surface ----------

@patch.object(handler, "s3")
def test_snapshot_download_takes_every_terraform_file_type(mock_s3):
    """Until this, only .tf came down. A hardcoded password lives in the
    .tfvars that was never uploaded, and a .tf.json module was invisible."""
    mock_s3.get_paginator.return_value.paginate.return_value = [{"Contents": [
        {"Key": "scans/pr-1/main.tf"},
        {"Key": "scans/pr-1/modules/vpc/main.tf.json"},
        {"Key": "scans/pr-1/terraform.tfvars"},
        {"Key": "scans/pr-1/prod.auto.tfvars.json"},
        {"Key": "scans/pr-1/README.md"},
        {"Key": "scans/pr-1/.terraform.lock.hcl"},
    ]}]

    with patch.object(handler.os, "makedirs"):
        downloaded = handler._download_snapshot("bucket", "scans/pr-1/", "/tmp/x")

    assert [pathlib_name(p) for p in downloaded] == [
        "main.tf", "main.tf.json", "terraform.tfvars", "prod.auto.tfvars.json",
    ]


def pathlib_name(path):
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def test_checkov_reports_may_be_a_list_when_two_frameworks_fire():
    """With `terraform,secrets`, checkov unwraps a lone report to a dict and
    leaves several as a list. Every consumer has to accept both, or a scan
    that finds a secret would drop every terraform finding alongside it."""
    terraform = _checkov_report(failed_checks=[{
        "check_id": "CKV_AWS_145", "file_path": "/main.tf",
        "file_line_range": [1, 3], "severity": None,
    }])
    secrets = {
        "check_type": "secrets",
        "results": {"failed_checks": [{
            "check_id": "CKV_SECRET_10", "file_path": "/terraform.tfvars",
            "file_line_range": [2, 2], "severity": None,
        }], "parsing_errors": []},
        "summary": {},
    }

    findings = handler._normalize_checkov([terraform, secrets], "pr-1")

    assert [(f["rule_id"], f["file"]) for f in findings] == [
        ("CKV_AWS_145", "main.tf"), ("CKV_SECRET_10", "terraform.tfvars"),
    ]
    # And the dict shape still works exactly as before.
    assert len(handler._normalize_checkov(terraform, "pr-1")) == 1


def test_parse_errors_are_collected_across_every_report():
    reports = [
        _checkov_report(parsing_errors=[f"{WORK_DIR}/a.tf"]),
        {"check_type": "secrets", "results": {"parsing_errors": [f"{WORK_DIR}/b.tfvars"]}},
    ]
    assert handler._checkov_parse_errors(reports, WORK_DIR) == ["a.tf", "b.tfvars"]


@patch.object(handler.subprocess, "run")
def test_checkov_runs_the_secrets_framework_too(mock_run):
    mock_run.return_value = _proc(stdout=json.dumps(_checkov_report()))

    handler._run_checkov(WORK_DIR)

    argv = mock_run.call_args.args[0]
    assert argv[argv.index("--framework") + 1] == "terraform,secrets"
    # Without this the secrets runner skips .tfvars: it is not on checkov's
    # SUPPORTED_FILE_EXTENSIONS, and that is where the passwords are.
    assert "--enable-secret-scan-all-files" in argv


# ---------- parse errors ----------

def test_parse_errors_are_reported_relative_to_the_work_dir():
    """checkov reports parsing_errors as the absolute path it walked, unlike
    its check records -- callers key on the same relative path the findings
    use, so both have to come back in the same form."""
    report = _checkov_report(parsing_errors=[f"{WORK_DIR}/main.tf", f"{WORK_DIR}/modules/vpc/net.tf"])

    assert handler._checkov_parse_errors(report, WORK_DIR) == ["main.tf", "modules/vpc/net.tf"]


def test_paths_are_relativized_whether_or_not_the_leading_slash_survived():
    """checkov's parsing_errors are absolute; tfsec, before Trivy, kept the
    leading slash in its findings and dropped it in its parse errors. Both
    forms are still accepted."""
    assert handler._relativize_path(f"{WORK_DIR}/main.tf", WORK_DIR) == "main.tf"
    assert handler._relativize_path(f"{WORK_DIR.lstrip('/')}/main.tf", WORK_DIR) == "main.tf"
    assert handler._relativize_path("/main.tf", WORK_DIR) == "main.tf"


def test_a_clean_report_has_no_parse_errors():
    assert handler._checkov_parse_errors(_checkov_report(), WORK_DIR) == []


def test_checkovs_bare_summary_shape_is_not_read_as_unknown():
    """When a report holds nothing at all, checkov drops "results" and emits
    only a summary. Parsing errors would themselves make the report non-empty
    (Report.is_empty counts them upstream), so this shape means zero parse
    errors -- not that the answer is unavailable."""
    bare_summary = {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0,
                    "resource_count": 0, "checkov_version": "3.2.0"}

    assert handler._checkov_parse_errors(bare_summary, WORK_DIR) == []


def _emf_lines(captured_out):
    """Every EMF record in stdout, parsed, with the shape CloudWatch requires
    checked: an _aws block whose metric names and dimension keys all exist as
    top-level fields. A record that fails this is silently ignored by
    CloudWatch, which is the failure mode a test has to catch."""
    records = []
    for line in captured_out.splitlines():
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if "_aws" not in rec:
            continue
        aws = rec["_aws"]
        assert isinstance(aws["Timestamp"], int)
        for block in aws["CloudWatchMetrics"]:
            assert block["Namespace"] == "IaCPosture"
            for dim_set in block["Dimensions"]:
                for key in dim_set:
                    assert key in rec, f"dimension {key} has no value"
            for m in block["Metrics"]:
                assert m["Name"] in rec, f"metric {m['Name']} has no value"
                assert isinstance(rec[m["Name"]], (int, float))
        records.append(rec)
    return records


# ---------- handler() ----------

@patch.object(handler, "_write_findings", return_value=(0, 0))
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_handler_surfaces_parse_errors_without_discarding_real_findings(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    """One unparseable file among several doesn't invalidate the others'
    findings, so this is reported rather than raised."""
    mock_download.return_value = ["main.tf", "broken.tf"]
    mock_trivy.return_value = ([{
        "ID": "AWS-0132", "Target": "main.tf", "Severity": "HIGH",
        "CauseMetadata": {"StartLine": 1, "EndLine": 3},
    }], [])
    mock_checkov.return_value = _checkov_report(parsing_errors=["broken.tf"])

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)

    assert result["scan_errors"] == ["broken.tf"]
    assert result["finding_count"] == 1
    mock_write.assert_called_once()


@patch.object(handler, "_write_findings", return_value=(0, 0))
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_a_persisted_scan_emits_findings_per_scan_as_emf(
    mock_download, mock_trivy, mock_checkov, mock_write, capsys
):
    """Spec §4.1's findings-per-scan metric, as one Embedded Metric Format
    line on stdout. Printed rather than logged: Lambda prefixes logger output
    and EMF needs the whole event to be the JSON."""
    mock_download.return_value = ["main.tf"]
    mock_trivy.return_value = ([{
        "ID": "AWS-0132", "Target": "main.tf", "Severity": "HIGH",
        "CauseMetadata": {"StartLine": 1, "EndLine": 3},
    }] * 3, [])
    mock_checkov.return_value = _checkov_report(parsing_errors=["broken.tf"])

    handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)

    records = _emf_lines(capsys.readouterr().out)
    assert len(records) == 1
    rec = records[0]
    assert rec["FindingsPerScan"] == 3
    assert rec["ScanParseErrors"] == 1
    assert rec["Environment"] == handler.ENVIRONMENT
    assert rec["pr_id"] == "pr-1"


@patch.object(handler, "_write_findings", return_value=(0, 0))
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_a_self_check_scan_emits_no_metric(
    mock_download, mock_trivy, mock_checkov, mock_write, capsys
):
    """persist=False is a rescan of one patched file for a self-check, not a
    scan of a PR. Counting it would make every remediation run look like a
    burst of tiny scans."""
    mock_download.return_value = ["main.tf"]
    mock_trivy.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    handler.handler({"pr_id": "pr-1", "s3_prefix": "fixes/pr-1/f1/", "persist": False}, None)

    assert _emf_lines(capsys.readouterr().out) == []


@patch.object(handler, "_write_findings", return_value=(0, 0))
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_handler_reports_no_scan_errors_on_a_clean_scan(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    mock_download.return_value = ["main.tf"]
    mock_trivy.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/", "persist": False}, None)

    assert result["scan_errors"] == []
    assert result["findings"] == []
    mock_write.assert_not_called()


@patch.object(handler, "_write_findings", return_value=(0, 0))
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_handler_merges_parse_errors_from_both_tools(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    """The two parsers disagree on what they can read, so neither alone is the
    oracle -- and a file they both choke on must be listed once, not twice.

    Paths are given already-relative here because handler() scans into a work
    dir it names itself; relativizing the absolute forms the tools really emit
    is covered by _relativize_path and _checkov_parse_errors directly."""
    mock_download.return_value = ["main.tf", "odd.tf"]
    mock_trivy.return_value = ([], ["main.tf"])
    mock_checkov.return_value = _checkov_report(parsing_errors=["main.tf", "odd.tf"])

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/", "persist": False}, None)

    assert result["scan_errors"] == ["main.tf", "odd.tf"]


@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_handler_lets_a_scanner_failure_reach_the_caller(mock_download, mock_trivy):
    """remediation-agent turns this into a failed Lambda invocation and leaves
    the finding at status "mapped" for a retry, rather than scoring the fix."""
    mock_download.return_value = ["main.tf"]
    mock_trivy.side_effect = handler.ScannerError("trivy produced no output (exit 126)")

    with pytest.raises(handler.ScannerError):
        handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)


# ---------- the fixture ----------

def test_the_unparseable_fixture_is_actually_unparseable():
    """Guards the fixture itself: it only tests anything if the brace really is
    missing. A well-meant edit that balanced it would leave every test above
    passing while the case they describe quietly stopped existing."""
    content = (FIXTURES / "unparseable" / "main.tf").read_text()

    assert content.count("{") > content.count("}")


# ---------- a re-scan does not reset what was decided ----------
#
# A plain put_item overwrote the whole record, so every re-scan sent each
# finding that still fired back to status "raw" with no mapping and no fix.
# The review of the previous push cannot be erased by the next one.

def _finding(finding_id="f1", pr_id="pr-1", **over):
    f = {
        "pk": f"PR#{pr_id}", "sk": f"FINDING#{finding_id}", "finding_id": finding_id,
        "target_type": "terraform", "finding_class": "misconfiguration",
        "source": "trivy", "rule_id": "AWS-0107",
        "file": "main.tf", "line_range": [10, 10], "severity": "HIGH",
        "control_mappings": [], "status": "raw", "proposed_fix": None,
        "created_at": "2026-09-01T00:00:00+00:00", "updated_at": "2026-09-01T00:00:00+00:00",
    }
    f.update(over)
    return f


def _write(mock_dynamodb, findings, known_ids=()):
    """Run _write_findings against a table holding known_ids already."""
    mock_table = MagicMock()
    mock_table.query.return_value = {"Items": [{"finding_id": i} for i in known_ids]}
    mock_dynamodb.Table.return_value = mock_table
    preserved, stale = handler._write_findings("pr-1", findings)
    return mock_table, preserved, stale


def _update_for(mock_table, finding_id):
    for call in mock_table.update_item.call_args_list:
        if call.kwargs["Key"]["sk"] == f"FINDING#{finding_id}":
            return call.kwargs
    raise AssertionError(f"no update for {finding_id}")


@patch.object(handler, "dynamodb")
def test_a_finding_that_fires_again_keeps_what_was_decided(mock_dynamodb):
    """The point of the change. status, control_mappings and proposed_fix are
    written only if absent, so a reviewed finding survives the next scan;
    severity and the timestamps are the scanner's and are refreshed."""
    mock_table, preserved, stale = _write(mock_dynamodb, [_finding()], known_ids=["f1"])

    assert (preserved, stale) == (1, 0)
    expr = _update_for(mock_table, "f1")["UpdateExpression"]
    # The two axes are the scanner's to refresh, and the field they replaced
    # is dropped so a re-scanned record migrates itself.
    assert "target_type = :target_type" in expr
    assert "finding_class = :finding_class" in expr
    assert "REMOVE no_longer_detected, iac_type" in expr
    for owned in ("#status = if_not_exists(#status, :raw)",
                  "control_mappings = if_not_exists(control_mappings, :empty)",
                  "proposed_fix = if_not_exists(proposed_fix, :null)",
                  "created_at = if_not_exists(created_at, :now)"):
        assert owned in expr
    for scanner_owned in ("severity = :severity", "last_seen_at = :now", "updated_at = :now"):
        assert scanner_owned in expr
    # And nothing is put: a put would overwrite the whole item.
    mock_table.put_item.assert_not_called()


@patch.object(handler, "dynamodb")
def test_a_finding_seen_for_the_first_time_is_not_counted_as_preserved(mock_dynamodb):
    _, preserved, stale = _write(mock_dynamodb, [_finding()], known_ids=[])

    assert (preserved, stale) == (0, 0)


@patch.object(handler, "dynamodb")
def test_a_finding_that_stops_firing_is_marked_not_deleted(mock_dynamodb):
    """The fix may have landed, the file may be gone, or a tool upgrade may
    have dropped the rule -- they read the same from here, and deleting would
    take the audit trail with them (spec §8.1)."""
    mock_table, preserved, stale = _write(mock_dynamodb, [_finding("f1")], known_ids=["f1", "gone"])

    assert (preserved, stale) == (1, 1)
    mock_table.delete_item.assert_not_called()
    marked = _update_for(mock_table, "gone")
    assert marked["UpdateExpression"] == "SET no_longer_detected = :now"
    # Only the first scan that stops seeing it records when; a later scan
    # must not move the date forward.
    assert marked["ConditionExpression"] == "attribute_not_exists(no_longer_detected)"


@patch.object(handler, "dynamodb")
def test_a_finding_that_comes_back_loses_the_mark(mock_dynamodb):
    mock_table, _, _ = _write(mock_dynamodb, [_finding()], known_ids=["f1"])

    assert "REMOVE no_longer_detected" in _update_for(mock_table, "f1")["UpdateExpression"]


@patch.object(handler, "dynamodb")
def test_existing_ids_are_read_before_the_writes_and_projected(mock_dynamodb):
    """Read first, so "already there" means before this scan -- and only the
    id is fetched, since a PR's findings carry whole file diffs."""
    mock_table, _, _ = _write(mock_dynamodb, [_finding()], known_ids=["f1"])

    query = mock_table.query.call_args.kwargs
    assert query["ProjectionExpression"] == "finding_id"
    assert query["ExpressionAttributeValues"][":pk"] == "PR#pr-1"


@patch.object(handler, "dynamodb")
def test_the_known_id_query_pages_to_exhaustion(mock_dynamodb):
    """A Query caps at 1MB of read items. Under-reading would treat a known
    finding as new -- harmless -- but also miss that one stopped firing."""
    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [{"finding_id": "a"}], "LastEvaluatedKey": {"pk": "x", "sk": "y"}},
        {"Items": [{"finding_id": "b"}]},
    ]
    mock_dynamodb.Table.return_value = mock_table

    assert handler._existing_finding_ids(mock_table, "pr-1") == {"a", "b"}


@patch.object(handler, "_write_findings", return_value=(3, 2))
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_the_handler_reports_what_the_rescan_preserved(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    mock_download.return_value = ["main.tf"]
    mock_trivy.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)

    assert result["preserved_count"] == 3
    assert result["no_longer_detected_count"] == 2


@patch.object(handler, "_write_findings")
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_a_self_check_rescan_touches_nothing(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    """persist=false is remediation-agent proving a fix. It must not write --
    least of all mark every finding on the PR as no longer detected, which a
    rescan of one patched file would otherwise do."""
    mock_download.return_value = ["main.tf"]
    mock_trivy.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    result = handler.handler(
        {"pr_id": "pr-1", "s3_prefix": "fixes/pr-1/f1/", "persist": False}, None
    )

    mock_write.assert_not_called()
    assert result["preserved_count"] == 0
    assert result["no_longer_detected_count"] == 0


@patch.object(handler, "dynamodb")
def test_findings_that_collide_on_one_id_are_written_once(mock_dynamodb):
    """A finding id hashes the rule and location but not the resource
    address, so one rule on several resources sharing a line range collapses
    to one id -- four times each for AWS-0031 and CKV_AWS_51 on PugetScope's
    ecr module. The table holds one record per id, so the write and the
    counts have to agree with that."""
    twice = [_finding("f1"), _finding("f1"), _finding("f2")]

    mock_table, preserved, stale = _write(mock_dynamodb, twice, known_ids=["f1", "f2"])

    assert mock_table.update_item.call_count == 2
    assert preserved == 2  # distinct findings, not the three reported
    assert stale == 0
