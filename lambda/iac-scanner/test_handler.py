"""Tests for iac-scanner's handler.

No AWS calls are made -- S3, DynamoDB, and both scanner subprocesses are
mocked. The focus is the distinction the scanner owes its callers: a scan
that ran and found nothing, versus a scan that did not run or could not read
its input. Those used to be the same empty list, and remediation-agent reads
an empty list as proof that a fix worked.
"""

import json
import os
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
    """The flags that make a scan reproducible, complete, and confined to
    the languages we have gates for: the embedded bundle rather than a
    fetch; the checks shipped in the image under the namespace Trivy has to
    be told to evaluate, without which a check from disk loads and silently
    never fires; and an explicit scanner list, because Trivy scans every
    config type it knows by default."""
    mock_run.return_value = _proc(stdout=json.dumps(_trivy_report()), returncode=0)

    handler._run_trivy(WORK_DIR)

    args = mock_run.call_args.args[0]
    assert args[:3] == [handler.TRIVY_BIN, "config", WORK_DIR]
    assert "--skip-check-update" in args
    assert args[args.index("--config-check") + 1] == handler.TRIVY_CHECKS_DIR
    assert args[args.index("--check-namespaces") + 1] == "user"
    # The second half of language admission -- the download filter is the
    # first. Terraform covers OpenTofu; anything else needs its gates built
    # before it appears here (docs/multi-iac-spec.md §4). kubernetes joined
    # on 2026-09-20. azure-arm joined on 2026-09-22 and left again on
    # 2026-09-23: Trivy's ARM adapter cannot satisfy four of its own checks,
    # so KICS scans ARM and Bicep instead
    # (docs/trivy-azure-arm-adapter-gap.md).
    assert args[args.index("--misconfig-scanners") + 1] == "terraform,kubernetes"


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


def test_findings_carry_the_tool_s_own_words_and_the_resource_address():
    """A Trivy id is a number. On terragoat's s3.tf the model drafting a fix
    for AWS-0091 (ignore public ACLs) had only that id in front of it and
    added versioning instead; the title is what tells it what the rule
    means. The resource address is what lets remediation-agent see that a
    fix to one of five buckets in a file resolved *this* finding. Neither is
    in the id hash, so an old record gains them on its next scan."""
    [trivy] = handler._normalize_trivy(
        [{**TRIVY_SQS_MISCONF, "Description": "Queues should be encrypted at rest.",
          "Target": "main.tf", "Type": "terraform", "Class": "config"}],
        "pr-1",
    )
    assert trivy["title"] == "Unencrypted SQS queue."
    assert trivy["description"] == "Queues should be encrypted at rest."
    assert trivy["resource"] == "aws_sqs_queue.plain"

    [checkov] = handler._normalize_checkov(_checkov_report(failed_checks=[{
        "check_id": "CKV_AWS_145", "check_name": "Ensure that S3 buckets are encrypted with KMS by default",
        "resource": "aws_s3_bucket.financials", "file_path": "/main.tf",
        "file_line_range": [1, 3], "severity": None,
    }]), "pr-1")
    assert checkov["title"] == "Ensure that S3 buckets are encrypted with KMS by default"
    assert checkov["description"] == ""
    assert checkov["resource"] == "aws_s3_bucket.financials"

    # A report field the tool left out is an empty string, not a KeyError:
    # every record has the field, so readers need no fallback.
    [bare] = handler._normalize_trivy(
        [{"ID": "AWS-0001", "Target": "main.tf", "Type": "terraform", "Class": "config",
          "CauseMetadata": {"StartLine": 1, "EndLine": 1}}],
        "pr-1",
    )
    assert (bare["title"], bare["description"], bare["resource"]) == ("", "", "")


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


def test_an_opentofu_finding_is_labelled_opentofu_though_trivy_says_terraform():
    """Trivy has no OpenTofu scanner -- it parses .tofu with its terraform
    one and reports Type=terraform. The record says opentofu anyway, because
    a repository can hold both and a reviewer needs to know which file they
    are looking at. This is the only place the two disagree."""
    [finding] = handler._normalize_trivy([{
        **TRIVY_SQS_MISCONF, "Target": "main.tofu", "Type": "terraform", "Class": "config",
    }], "pr-1")

    assert finding["target_type"] == "opentofu"
    assert finding["finding_class"] == "misconfiguration"
    assert finding["rule_id"] == "AWS-0096"  # the same rules, unchanged


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
def test_snapshot_download_takes_every_file_type_the_scanner_reads(mock_s3):
    """Until this, only .tf came down. A hardcoded password lives in the
    .tfvars that was never uploaded, and a .tf.json module was invisible.
    .tofu/.tofu.json joined on 2026-09-16 -- and this is the test that
    notices if they leave: without them here, dropping either from
    SNAPSHOT_SUFFIXES fails nothing, because every other scanner test hands
    the file list in ready-made."""
    mock_s3.get_paginator.return_value.paginate.return_value = [{"Contents": [
        {"Key": "scans/pr-1/main.tf"},
        {"Key": "scans/pr-1/modules/vpc/main.tf.json"},
        {"Key": "scans/pr-1/terraform.tfvars"},
        {"Key": "scans/pr-1/prod.auto.tfvars.json"},
        {"Key": "scans/pr-1/main.tofu"},
        {"Key": "scans/pr-1/modules/vpc/net.tofu.json"},
        {"Key": "scans/pr-1/k8s/deploy.yaml"},
        {"Key": "scans/pr-1/k8s/service.yml"},
        {"Key": "scans/pr-1/infra/main.bicep"},
        {"Key": "scans/pr-1/README.md"},
        {"Key": "scans/pr-1/.terraform.lock.hcl"},
    ]}]

    with patch.object(handler.os, "makedirs"):
        downloaded, unreadable = handler._download_snapshot("bucket", "scans/pr-1/", "/tmp/x")

    assert [pathlib_name(p) for p in downloaded] == [
        "main.tf", "main.tf.json", "terraform.tfvars", "prod.auto.tfvars.json",
        "main.tofu", "net.tofu.json", "deploy.yaml", "service.yml", "main.bicep",
    ]
    assert unreadable == []


@patch.object(handler, "s3")
def test_the_snapshot_stops_at_the_languages_the_scanner_admits(mock_s3):
    """A language reaches the scanner only once its remediation gates exist
    (docs/multi-iac-spec.md §4). npm, Dockerfile and CloudFormation have
    none, so their files are not downloaded however well the tools would
    parse them. The download filter is the first of the two guards;
    --misconfig-scanners is the other.

    Bicep left this list on 2026-09-22 when its gates were built. The
    lockfile stays out for a stronger reason than a suffix: it is downloaded,
    sniffed, found not to carry an ARM $schema and removed again -- which is
    what admits a template named anything while excluding a .json that is not
    one."""
    mock_s3.get_paginator.return_value.paginate.return_value = [{"Contents": [
        {"Key": "scans/pr-1/package-lock.json"},
        {"Key": "scans/pr-1/Dockerfile"},
        {"Key": "scans/pr-1/cloudformation.template"},
    ]}]

    with patch.object(handler.os, "makedirs"), \
         patch.object(handler.os, "remove") as mock_remove, \
         patch("builtins.open", _reading('{"name": "decoy", "lockfileVersion": 3}')):
        downloaded, unreadable = handler._download_snapshot("bucket", "scans/pr-1/", "/tmp/x")

    assert downloaded == []
    assert unreadable == []
    # Removed from the work dir, not merely left off the list: checkov's
    # secrets runner is given --enable-secret-scan-all-files and reads the
    # directory.
    assert mock_remove.call_count == 1


@patch.object(handler.subprocess, "run")
def test_helm_is_not_admitted_even_though_trivy_supports_it(mock_run):
    """The one exclusion that is not about missing gates. Chart files are in
    the snapshot already (they are .yaml), and Trivy renders charts natively,
    so enabling `helm` would be one word. It stays off because the self-check
    scans a single corrected file in isolation: a template without its
    Chart.yaml and values.yaml renders nothing, no findings come back, and
    this pipeline reads no findings as "the fix worked". That is the
    fail-open §4 exists to prevent, so the word stays out until the
    self-check can render a chart. See multi-iac-spec §6 step 3."""
    mock_run.return_value = _proc(stdout=json.dumps(_trivy_report()), returncode=0)

    handler._run_trivy(WORK_DIR)

    args = mock_run.call_args.args[0]
    scanners = args[args.index("--misconfig-scanners") + 1].split(",")
    assert "helm" not in scanners
    # The same reasoning, from the other side: these have no gates at all.
    assert not {"cloudformation", "dockerfile", "ansible"} & set(scanners)
    # azure-arm is excluded for a different reason from the rest: not missing
    # gates but a broken adapter, with KICS covering the language instead.
    assert "azure-arm" not in scanners


# ---------- KICS: ARM and Bicep ----------

def _kics_report(queries=(), files_scanned=1, files_parsed=1):
    """KICS's JSON report shape, as v2.1.20 emits it."""
    return {
        "files_scanned": files_scanned,
        "files_parsed": files_parsed,
        "files_failed_to_scan": 0,
        "total_counter": sum(len(q.get("files") or []) for q in queries),
        "queries": list(queries),
    }


def _no_kics(work_dir):
    """KICS returning nothing, for the handler() tests that are about the
    other two tools. Applied with `new=` so it adds no positional argument to
    the test signatures it decorates."""
    return _kics_report()


KICS_STORAGE_QUERY = {
    "query_id": "1367dd13-0ee9-4c8a-8a2b-2b2b6c2ba1ba",
    "query_name": "Storage Account Allows Unsecure Transfer",
    "severity": "MEDIUM",
    "category": "Encryption",
    "description": "Make sure that Storage Accounts only allow secure transfer.",
    "files": [{
        "file_name": "main.bicep",
        "line": 10,
        "resource_name": "stgevalinsecure",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "search_key": "resources.name=stgevalinsecure.properties.supportsHttpsTrafficOnly",
    }],
}


def test_kics_findings_normalize_to_the_record_shape():
    """The query's UUID as the rule id, not its name: the name is prose and
    has been reworded upstream, where the id is the rule's identity and is
    what corpus/rule_mappings.json is keyed on. The name rides along as the
    title so a reviewer and the remediation prompt still get words."""
    [finding] = handler._normalize_kics(_kics_report([KICS_STORAGE_QUERY]), ".", "pr-1")

    assert finding["source"] == "kics"
    assert finding["rule_id"] == "1367dd13-0ee9-4c8a-8a2b-2b2b6c2ba1ba"
    assert finding["title"] == "Storage Account Allows Unsecure Transfer"
    assert finding["file"] == "main.bicep"
    assert finding["line_range"] == [10, 10]
    assert finding["severity"] == "MEDIUM"
    assert finding["target_type"] == "bicep"
    assert finding["finding_class"] == "misconfiguration"
    assert finding["resource"] == "stgevalinsecure"


def test_kics_reports_a_severity_where_checkov_reports_none():
    """The reason a severity floor was ruled out for Azure (multi-iac-spec
    §5.1 fact 1) was that checkov reports no severity and Trivy was the only
    source. KICS reports one on every finding, so that reasoning no longer
    holds for ARM and Bicep."""
    report = _kics_report([{**KICS_STORAGE_QUERY, "severity": "CRITICAL"}])

    [finding] = handler._normalize_kics(report, ".", "pr-1")

    assert finding["severity"] == "CRITICAL"


def test_a_kics_secret_finding_is_classed_as_a_secret():
    """finding_class branches the pipeline, and KICS puts its credential
    queries in one category rather than naming them individually."""
    report = _kics_report([{
        **KICS_STORAGE_QUERY,
        "query_id": "487f4be7-3fd9-4506-a07a-eae252180c08",
        "query_name": "Passwords And Secrets - Generic Password",
        "category": "Secret Management",
    }])

    [finding] = handler._normalize_kics(report, ".", "pr-1")

    assert finding["finding_class"] == "secret"
    assert finding["target_type"] == "bicep"


def test_a_kics_path_is_reported_relative_to_the_work_dir(tmp_path):
    """KICS reports each file relative to its own working directory, which it
    inherits from this process -- so a file in /tmp/scan-abc comes back as
    ../../tmp/scan-abc/main.bicep. Every other path in a finding is
    work_dir-relative and remediation-agent matches on it."""
    work_dir = str(tmp_path / "scan-abc")
    reported = os.path.join(work_dir, "modules", "storage.bicep")

    assert handler._relativize_kics_path(reported, work_dir) == "modules/storage.bicep"


def test_kics_writing_no_report_is_a_failed_scan_not_a_clean_one(tmp_path):
    """The same false-pass path Trivy's empty stdout guards: KICS writes a
    report even when it finds nothing, so a missing one means the binary
    failed -- and returning no findings for that would tell
    remediation-agent the file is clean."""
    with patch.object(handler.subprocess, "run") as mock_run:
        mock_run.return_value = _proc(stdout="", stderr="exec format error", returncode=126)

        with pytest.raises(handler.ScannerError, match="kics wrote no report"):
            handler._run_kics(str(tmp_path))


def test_kics_is_run_offline_against_the_bundled_queries(tmp_path):
    """No egress from the function: --disable-full-descriptions stops the one
    call KICS would otherwise make, and the queries come from the bundle in
    the image rather than a fetch. Verified under `--network none`
    2026-09-23."""
    report_dir = {}

    def fake_run(argv, **kwargs):
        # write the report where the handler will look for it
        out = argv[argv.index("-o") + 1]
        report_dir["path"] = out
        with open(os.path.join(out, "kics.json"), "w", encoding="utf-8") as fh:
            json.dump(_kics_report(), fh)
        return _proc(returncode=0)

    with patch.object(handler.subprocess, "run", side_effect=fake_run) as mock_run:
        handler._run_kics(str(tmp_path))

    argv = mock_run.call_args.args[0]
    assert argv[0] == handler.KICS_BIN
    assert "--disable-full-descriptions" in argv
    assert argv[argv.index("-t") + 1] == handler.KICS_PLATFORM
    assert argv[argv.index("-q") + 1].startswith(handler.KICS_ASSETS_DIR)
    assert argv[argv.index("-b") + 1].startswith(handler.KICS_ASSETS_DIR)
    # the report directory is cleaned up whatever happened
    assert not os.path.exists(report_dir["path"])


def test_kics_covers_bicep_so_it_is_no_longer_single_source():
    """The measurement that retires multi-iac-spec §4's Bicep caveat: Trivy
    has no Bicep scanner, but KICS parses .bicep natively, so a Bicep
    finding's self-check now compares two sources rather than one."""
    report = _kics_report([KICS_STORAGE_QUERY])

    findings = handler._normalize_kics(report, ".", "pr-1")

    assert {f["target_type"] for f in findings} == {"bicep"}
    assert {f["source"] for f in findings} == {"kics"}


def test_kics_files_it_could_not_parse_are_counted_even_though_unnamed():
    """KICS reports files_failed_to_scan: 0 even when it has silently dropped
    a file -- measured 2026-09-23 on a deliberately broken template. The gap
    between scanned and parsed is the only signal it gives, and it is a count
    without names, so it is logged rather than put in scan_errors, which is a
    list of files."""
    assert handler._kics_unparsed_count(_kics_report(files_scanned=3, files_parsed=1)) == 2
    assert handler._kics_unparsed_count(_kics_report(files_scanned=2, files_parsed=2)) == 0


def pathlib_name(path):
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _reading(text):
    """A `builtins.open` stand-in whose file reads back as `text`."""
    handle = MagicMock()
    handle.__enter__.return_value.read.return_value = text
    return MagicMock(return_value=handle)


ARM_TEMPLATE = json.dumps({
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [{"type": "Microsoft.Storage/storageAccounts", "name": "stg"}],
})


@patch.object(handler, "s3")
def test_a_json_is_downloaded_only_if_its_schema_says_arm(mock_s3):
    """ARM is admitted by content, not by name. On
    azure-quickstart-templates the tree holds 519 .json files of which 175
    are templates and 159 of the rest are azuredeploy.parameters.json -- a
    name-based rule admits those and this one does not, while still admitting
    a template called anything at all."""
    mock_s3.get_paginator.return_value.paginate.return_value = [{"Contents": [
        {"Key": "scans/pr-1/infra/whatever-we-called-it.json"},
    ]}]

    with patch.object(handler.os, "makedirs"), patch("builtins.open", _reading(ARM_TEMPLATE)):
        downloaded, unreadable = handler._download_snapshot("bucket", "scans/pr-1/", "/tmp/x")

    assert [pathlib_name(p) for p in downloaded] == ["whatever-we-called-it.json"]
    assert unreadable == []


@patch.object(handler, "s3")
def test_an_arm_template_that_is_not_valid_json_is_a_scan_error_not_a_silent_skip(mock_s3):
    """The fail-open this sniff has to avoid. A .json that claims the ARM
    schema and will not parse might be the template a fix just broke, and
    dropping it silently gives the self-check zero findings to read as "the
    fix worked". Neither tool reports it -- Trivy logs nothing for ARM at all
    (measured 2026-09-22) -- so this is the only detection there is."""
    mock_s3.get_paginator.return_value.paginate.return_value = [{"Contents": [
        {"Key": "scans/pr-1/azuredeploy.json"},
    ]}]
    broken = ARM_TEMPLATE[: ARM_TEMPLATE.index('"resources"') + 14]

    with patch.object(handler.os, "makedirs"), patch.object(handler.os, "remove"), \
         patch("builtins.open", _reading(broken)):
        downloaded, unreadable = handler._download_snapshot("bucket", "scans/pr-1/", "/tmp/x")

    assert downloaded == []
    assert unreadable == ["azuredeploy.json"]


def test_a_json_that_merely_mentions_the_schema_string_is_not_admitted():
    """The regex is a cheap gate so json.loads is never called on a large
    lockfile; the parsed check behind it is what decides. A file with the
    words in its data does not become a template."""
    assert handler._arm_verdict(json.dumps({"docs": "see deploymentTemplate.json for the $schema"})) == "not-arm"
    assert handler._arm_verdict(ARM_TEMPLATE) == "arm"
    assert handler._arm_verdict('{"name": "lockfile"}') == "not-arm"


def test_a_tf_json_is_terraform_not_arm():
    """Suffix order matters: .tf.json and .tofu.json are claimed before the
    bare .json entry that exists for ARM."""
    assert handler._target_type_for("main.tf.json", "terraform") == "terraform"
    assert handler._target_type_for("net.tofu.json", "terraform") == "opentofu"
    assert handler._target_type_for("prod.auto.tfvars.json", "") == "terraform"
    assert handler._target_type_for("azuredeploy.json", "azure-arm") == "arm"


def test_trivys_azure_arm_and_checkovs_arm_become_one_target_type():
    """Trivy calls the target azure-arm and checkov calls it arm. Two
    spellings would be two dashboard groups and, worse, one target_type with
    no structural guard registered against it."""
    assert handler._target_type_for("templates/deploy", "azure-arm") == "arm"
    assert handler._target_type_for("templates/deploy", "arm") == "arm"


def test_a_secret_in_a_bicep_file_is_bicep_and_a_secret():
    """checkov's secrets runner reports check_type "secrets", which names a
    discipline and no target, so the suffix has to supply it. Left as
    "unknown" this finding would be refused by remediation-agent's structural
    guard rather than remediated."""
    assert handler._target_type_for("infra/main.bicep", "") == "bicep"


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
    assert argv[argv.index("--framework") + 1] == "terraform,kubernetes,arm,bicep,secrets"
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


# ---------- the parse check neither tool performs ----------

BROKEN_MANIFEST = """apiVersion: v1
kind: Pod
metadata:
  name: broken
spec:
  containers:
  - name: c
    image: nginx
   badly: [indented
"""

VALID_MANIFEST = """apiVersion: v1
kind: Pod
metadata:
  name: fine
spec:
  containers:
  - name: c
    image: nginx:1.27
"""


def test_a_manifest_that_does_not_parse_is_a_scan_error_though_neither_tool_reports_it(tmp_path):
    """The hole this function exists for, measured 2026-09-22 against the
    pinned tools: Trivy says "Detected config files num=0" and logs nothing,
    and checkov's kubernetes runner emits no report at all -- not even a
    parsing_errors entry. So a fix that broke a manifest's YAML came back
    with zero findings and an empty scan_errors, which is exactly what
    remediation-agent's self-check reads as "the fix worked"."""
    (tmp_path / "manifest.yaml").write_text(BROKEN_MANIFEST, encoding="utf-8")
    downloaded = [str(tmp_path / "manifest.yaml")]

    assert handler._unparseable_admitted_files(downloaded, str(tmp_path)) == ["manifest.yaml"]


def test_a_valid_manifest_is_not_a_scan_error(tmp_path):
    (tmp_path / "manifest.yaml").write_text(VALID_MANIFEST, encoding="utf-8")
    downloaded = [str(tmp_path / "manifest.yaml")]

    assert handler._unparseable_admitted_files(downloaded, str(tmp_path)) == []


# A CloudFormation template in the style people actually write: short-form
# intrinsics throughout, in all three node shapes a constructor has to take.
CFN_TEMPLATE_WITH_INTRINSICS = """AWSTemplateFormatVersion: '2010-09-09'

Conditions:
  HasTags: !Equals [!Ref Env, prod]

Resources:
  LogsBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${AWS::StackName}-logs'
      LoggingConfiguration: !If [HasTags, {DestinationBucketName: !Ref Other}, !Ref 'AWS::NoValue']

Outputs:
  Arn:
    Value: !GetAtt LogsBucket.Arn
  Joined:
    Value: !Join [',', [!Ref LogsBucket, !GetAtt LogsBucket.Arn]]
"""


def test_a_cloudformation_template_is_not_reported_as_unparseable(tmp_path):
    """CloudFormation's short-form intrinsics are YAML *tags*, and a stock
    PyYAML has no constructor for them -- `!Sub` raises ConstructorError,
    which is a YAMLError and so was caught here as an unreadable file.

    A .yaml is downloaded whatever it turns out to be, so this misreported
    every idiomatic template from the day .yaml was admitted, well before
    CloudFormation was a target. The direction is the safe one -- a scan
    error holds a fix rather than passing it -- but it is still a readable
    file reported as unreadable, and it would block remediation across the
    whole language once CloudFormation is admitted."""
    (tmp_path / "template.yaml").write_text(CFN_TEMPLATE_WITH_INTRINSICS,
                                            encoding="utf-8")
    downloaded = [str(tmp_path / "template.yaml")]

    assert handler._unparseable_admitted_files(downloaded, str(tmp_path)) == []


def test_an_unknown_tag_is_still_a_scan_error(tmp_path):
    """The tags are enumerated, not matched as a `!` prefix. A prefix rule is
    the shorter version of this and would accept any tag at all -- so a
    genuinely broken file would parse and this check would under-report,
    which is the failure it exists to prevent."""
    (tmp_path / "manifest.yaml").write_text("spec: !Whatever value\n",
                                            encoding="utf-8")
    downloaded = [str(tmp_path / "manifest.yaml")]

    assert handler._unparseable_admitted_files(downloaded, str(tmp_path)) == \
        ["manifest.yaml"]


def test_the_cfn_tags_do_not_make_a_broken_manifest_parse(tmp_path):
    """The Kubernetes guarantee is unchanged by the CloudFormation one. The
    tab-indented Service from argocd-example-apps is the case found in the
    wild, and it has to keep failing."""
    (tmp_path / "svc.yaml").write_text("metadata:\n\tname: guestbook\n",
                                       encoding="utf-8")
    downloaded = [str(tmp_path / "svc.yaml")]

    assert handler._unparseable_admitted_files(downloaded, str(tmp_path)) == \
        ["svc.yaml"]


def test_a_helm_template_is_not_reported_as_unparseable(tmp_path):
    """A chart template is not valid YAML until it is rendered, and helm is
    deliberately not admitted -- so this is a file the scanner does not
    handle, not one it failed to read. Reporting it would put a scan error on
    every repository carrying a chart, and two of the external baselines
    carry one; multi-iac-spec §6 step 3 measured that cost as zero noise and
    this keeps it there."""
    template = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
        '  name: {{ include "web.fullname" . }}\n'
        "spec:\n  replicas: {{ .Values.replicaCount }}\n"
    )
    (tmp_path / "deployment.yaml").write_text(template, encoding="utf-8")

    assert handler._unparseable_admitted_files([str(tmp_path / "deployment.yaml")],
                                               str(tmp_path)) == []


def test_the_parse_check_reports_paths_relative_to_the_work_dir(tmp_path):
    """Every other entry in scan_errors is work_dir-relative, and
    remediation-agent matches them against a finding's file path."""
    nested = tmp_path / "k8s" / "base"
    nested.mkdir(parents=True)
    (nested / "deploy.yml").write_text(BROKEN_MANIFEST, encoding="utf-8")

    assert handler._unparseable_admitted_files([str(nested / "deploy.yml")],
                                               str(tmp_path)) == ["k8s/base/deploy.yml"]


def test_a_snapshot_with_no_yaml_never_reaches_pyyaml(tmp_path):
    """A Terraform-only scan must not depend on the import at all -- that is
    what makes reading PyYAML off /opt/python safe rather than a new runtime
    dependency."""
    with patch.object(handler, "_yaml_module", side_effect=AssertionError("must not import")):
        assert handler._unparseable_admitted_files([str(tmp_path / "main.tf")], str(tmp_path)) == []


def test_a_missing_pyyaml_is_a_failed_scan_not_an_unchecked_one(tmp_path):
    """A parse check that quietly does not run is the same fail-open it was
    written to close, so the scan is refused rather than reported."""
    (tmp_path / "manifest.yaml").write_text(VALID_MANIFEST, encoding="utf-8")

    with patch.dict("sys.modules", {"yaml": None}):
        with pytest.raises(handler.ScannerError, match="PyYAML"):
            handler._unparseable_admitted_files([str(tmp_path / "manifest.yaml")], str(tmp_path))


def test_a_parse_error_from_a_non_terraform_parser_is_still_a_scan_error():
    """The regex names the parser generically. Trivy does not in fact log one
    for ARM or Kubernetes (measured 2026-09-22, which is why the check above
    exists), but a hardcoded "terraform" would make any it ever does log
    invisible -- and invisible is the direction that hands out a verified
    badge for a scan that did not happen."""
    stderr = (
        '2026-09-22T23:15:28Z\tERROR\t[azure-arm parser] Error parsing file\t'
        'module="root" file_path="azuredeploy.json" cause="..." err="unexpected end of JSON input"\n'
    )

    assert handler.TRIVY_PARSE_ERROR_RE.findall(stderr) == ["azuredeploy.json"]


def test_the_terraform_parse_error_line_still_matches_verbatim():
    """The widening must not lose the form it was built from."""
    assert handler.TRIVY_PARSE_ERROR_RE.findall(TRIVY_PARSE_FAILURE_STDERR) == ["bad.tf", "bad.tf"]


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
@patch.object(handler, "_run_kics", new=_no_kics)
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_handler_surfaces_parse_errors_without_discarding_real_findings(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    """One unparseable file among several doesn't invalidate the others'
    findings, so this is reported rather than raised."""
    mock_download.return_value = (["main.tf", "broken.tf"], [])
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
@patch.object(handler, "_run_kics", new=_no_kics)
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_a_persisted_scan_emits_findings_per_scan_as_emf(
    mock_download, mock_trivy, mock_checkov, mock_write, capsys
):
    """Spec §4.1's findings-per-scan metric, as one Embedded Metric Format
    line on stdout. Printed rather than logged: Lambda prefixes logger output
    and EMF needs the whole event to be the JSON."""
    mock_download.return_value = (["main.tf"], [])
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
@patch.object(handler, "_run_kics", new=_no_kics)
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_a_self_check_scan_emits_no_metric(
    mock_download, mock_trivy, mock_checkov, mock_write, capsys
):
    """persist=False is a rescan of one patched file for a self-check, not a
    scan of a PR. Counting it would make every remediation run look like a
    burst of tiny scans."""
    mock_download.return_value = (["main.tf"], [])
    mock_trivy.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    handler.handler({"pr_id": "pr-1", "s3_prefix": "fixes/pr-1/f1/", "persist": False}, None)

    assert _emf_lines(capsys.readouterr().out) == []


@patch.object(handler, "_write_findings", return_value=(0, 0))
@patch.object(handler, "_run_kics", new=_no_kics)
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_handler_reports_no_scan_errors_on_a_clean_scan(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    mock_download.return_value = (["main.tf"], [])
    mock_trivy.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/", "persist": False}, None)

    assert result["scan_errors"] == []
    assert result["findings"] == []
    mock_write.assert_not_called()


@patch.object(handler, "_write_findings", return_value=(0, 0))
@patch.object(handler, "_run_kics", new=_no_kics)
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
    mock_download.return_value = (["main.tf", "odd.tf"], [])
    mock_trivy.return_value = ([], ["main.tf"])
    mock_checkov.return_value = _checkov_report(parsing_errors=["main.tf", "odd.tf"])

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/", "persist": False}, None)

    assert result["scan_errors"] == ["main.tf", "odd.tf"]


@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_handler_lets_a_scanner_failure_reach_the_caller(mock_download, mock_trivy):
    """remediation-agent turns this into a failed Lambda invocation and leaves
    the finding at status "mapped" for a retry, rather than scoring the fix."""
    mock_download.return_value = (["main.tf"], [])
    mock_trivy.side_effect = handler.ScannerError("trivy produced no output (exit 126)")

    with pytest.raises(handler.ScannerError):
        handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)


@patch.object(handler, "_write_findings", return_value=(0, 0))
@patch.object(handler, "_run_kics", new=_no_kics)
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_a_mixed_snapshot_labels_each_file_by_its_own_suffix(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    """OpenTofu and Terraform in one repository -- which OpenTofu itself
    allows, preferring .tofu where both exist. target_type is per finding,
    not per scan, so the two do not smear into one label."""
    mock_download.return_value = (["main.tf", "main.tofu"], [])
    mock_trivy.return_value = ([
        {"ID": "AWS-0132", "Target": "main.tf", "Severity": "HIGH",
         "Type": "terraform", "Class": "config",
         "CauseMetadata": {"StartLine": 1, "EndLine": 3}},
        {"ID": "AWS-0132", "Target": "main.tofu", "Severity": "HIGH",
         "Type": "terraform", "Class": "config",
         "CauseMetadata": {"StartLine": 1, "EndLine": 3}},
    ], [])
    mock_checkov.return_value = _checkov_report()

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)

    by_file = {f["file"]: f for f in result["findings"]}
    assert by_file["main.tf"]["target_type"] == "terraform"
    assert by_file["main.tofu"]["target_type"] == "opentofu"
    # Same rule, same class, different target: the id hashes the rule and
    # location, so these stay two findings rather than colliding.
    assert by_file["main.tf"]["finding_id"] != by_file["main.tofu"]["finding_id"]


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
@patch.object(handler, "_run_kics", new=_no_kics)
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_the_handler_reports_what_the_rescan_preserved(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    mock_download.return_value = (["main.tf"], [])
    mock_trivy.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)

    assert result["preserved_count"] == 3
    assert result["no_longer_detected_count"] == 2


@patch.object(handler, "_write_findings")
@patch.object(handler, "_run_kics", new=_no_kics)
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_trivy")
@patch.object(handler, "_download_snapshot")
def test_a_self_check_rescan_touches_nothing(
    mock_download, mock_trivy, mock_checkov, mock_write
):
    """persist=false is remediation-agent proving a fix. It must not write --
    least of all mark every finding on the PR as no longer detected, which a
    rescan of one patched file would otherwise do."""
    mock_download.return_value = (["main.tf"], [])
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
