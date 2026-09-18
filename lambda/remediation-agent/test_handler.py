"""Tests for remediation-agent's handler.

No AWS/Anthropic calls are made -- DynamoDB, S3, the iac-scanner
Lambda invocation, and the Anthropic client are all mocked. The self-check
comparison tests use real captured iac-scanner output from
fixtures/ (see fixtures/README.md) rather than hand-written scan responses,
per that README's guidance to keep ground truth accurate.
"""

import collections
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import handler

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name, side):
    with open(FIXTURES / name / side / "scan-response.json") as f:
        return json.load(f)


def _read_fixture_tf(name, side):
    return (FIXTURES / name / side / "main.tf").read_text()


def _pairs(scan_response):
    """Baseline occurrence counts, as _chain_root derives them for a pristine root."""
    return collections.Counter(
        (f["source"], f["rule_id"]) for f in scan_response["findings"]
    )


# ---------- _evaluate_self_check ----------

def test_self_check_clean_fix_single_rule_clears():
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0132")
    baseline_pairs = _pairs(before)

    passed, new_findings, cleared = handler._evaluate_self_check(finding, after["findings"], baseline_pairs)

    assert passed is True
    assert new_findings == []
    assert cleared is True


@pytest.mark.parametrize("rule_id", ["CKV_AWS_24", "AWS-0107"])
def test_self_check_clean_fix_clears_multiple_sources_at_once(rule_id):
    before = _load_fixture("open-ssh-ingress", "before")
    after = _load_fixture("open-ssh-ingress", "after")
    finding = next(f for f in before["findings"] if f["rule_id"] == rule_id)
    baseline_pairs = _pairs(before)

    passed, new_findings, cleared = handler._evaluate_self_check(finding, after["findings"], baseline_pairs)

    assert passed is True
    assert new_findings == []
    assert cleared is True


def test_self_check_fails_when_original_finding_not_cleared():
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0132")
    baseline_pairs = _pairs(before)

    # Rescan identical to the baseline -- as if the "fix" changed nothing.
    passed, new_findings, cleared = handler._evaluate_self_check(finding, before["findings"], baseline_pairs)

    assert passed is False
    assert new_findings == []
    # The failing half: the finding is still there.
    assert cleared is False


def test_self_check_fails_when_fix_introduces_a_new_finding():
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0132")
    baseline_pairs = _pairs(before)

    rescan_findings = after["findings"] + [
        {"source": "trivy", "rule_id": "AWS-9999"}
    ]

    passed, new_findings, cleared = handler._evaluate_self_check(finding, rescan_findings, baseline_pairs)

    assert passed is False
    assert new_findings == ["trivy:AWS-9999"]
    # The other failure mode: the original cleared, the fix just brought new
    # findings with it. Collapsing this into "self-check failed" like cleared
    # is False would misreport a fix that's most of the way there.
    assert cleared is True


def test_self_check_clears_when_one_of_several_instances_is_fixed():
    """A file can hold the same rule several times. Fixing the flagged one
    leaves the others firing, and presence-based comparison would call that
    an uncleared finding."""
    before = _load_fixture("open-ssh-ingress", "before")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0107")
    target = (finding["source"], finding["rule_id"])

    baseline = collections.Counter({target: 3})
    rescan = [{"source": target[0], "rule_id": target[1]}] * 2  # one instance gone

    passed, new_findings, cleared = handler._evaluate_self_check(finding, rescan, baseline)

    assert cleared is True
    assert new_findings == []
    assert passed is True


def test_self_check_does_not_clear_when_instance_count_is_unchanged():
    before = _load_fixture("open-ssh-ingress", "before")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0107")
    target = (finding["source"], finding["rule_id"])

    baseline = collections.Counter({target: 3})
    rescan = [{"source": target[0], "rule_id": target[1]}] * 3  # nothing changed

    passed, _, cleared = handler._evaluate_self_check(finding, rescan, baseline)

    assert cleared is False
    assert passed is False


def test_a_rule_firing_several_times_at_one_location_is_one_finding():
    """Trivy reports AWS-0038 once per missing EKS log type, five times at
    the same cluster; the table keeps one record per id, so a baseline read
    from it says 1. Counted raw, every rescan of that file said 5 and every
    fix to it was rejected for "four new findings" -- terragoat's eks.tf,
    2026-09-18, 11 of 11. The unit is the id on both sides."""
    finding = {"source": "checkov", "rule_id": "CKV_AWS_39", "finding_id": "target"}
    logging = {"source": "trivy", "rule_id": "AWS-0038", "finding_id": "same-cluster"}

    baseline = collections.Counter({("checkov", "CKV_AWS_39"): 1, ("trivy", "AWS-0038"): 1})
    rescan = [logging] * 5  # fix cleared the target; logging still fires, once per log type

    passed, new_findings, cleared = handler._evaluate_self_check(finding, rescan, baseline)

    assert cleared is True
    assert new_findings == []
    assert passed is True


def test_the_same_rule_at_a_second_location_is_still_a_new_finding():
    """The dedup is by id, and an id includes the lines: a fix that adds a
    second cluster with the same gap has doubled the problem."""
    finding = {"source": "checkov", "rule_id": "CKV_AWS_39", "finding_id": "target"}
    baseline = collections.Counter({("checkov", "CKV_AWS_39"): 1, ("trivy", "AWS-0038"): 1})
    rescan = [
        {"source": "trivy", "rule_id": "AWS-0038", "finding_id": "cluster-a"},
        {"source": "trivy", "rule_id": "AWS-0038", "finding_id": "cluster-b"},
    ]

    passed, new_findings, cleared = handler._evaluate_self_check(finding, rescan, baseline)

    assert new_findings == ["trivy:AWS-0038"]
    assert passed is False


def test_extra_instance_of_an_existing_rule_counts_as_a_new_finding():
    """A fix that doubles a problem already present isn't clean, even though
    the rule was in the baseline."""
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0132")
    target = (finding["source"], finding["rule_id"])
    other = ("trivy", "AWS-0089")

    baseline = collections.Counter({target: 1, other: 1})
    rescan = [{"source": other[0], "rule_id": other[1]}] * 2  # target gone, other doubled

    passed, new_findings, cleared = handler._evaluate_self_check(finding, rescan, baseline)

    assert cleared is True
    assert new_findings == ["trivy:AWS-0089"]
    assert passed is False


# ---------- suppression rejection ----------

# The literal diff the agent produced against PugetScope's security groups: it
# left cidr_blocks = ["0.0.0.0/0"] untouched and silenced the rule instead.
PUGETSCOPE_SUPPRESSION_DIFF = '''--- a/modules/security_groups/main.tf
+++ b/modules/security_groups/main.tf
@@ -50,12 +50,16 @@
   description       = "HTTP for the public app via ingress"
 }

+# The application is intentionally served to the public internet over TLS on
+# 443 via the nginx ingress controller running on these nodes, so open HTTPS
+# ingress is required by design and is reviewed/accepted here.
+#tfsec:ignore:aws-ec2-no-public-ingress-sgr
 resource "aws_security_group_rule" "https_from_internet" {
   type              = "ingress"
-  cidr_blocks       = ["0.0.0.0/0"]
+  cidr_blocks       = ["0.0.0.0/0"] #tfsec:ignore:aws-ec2-no-public-ingress-sgr
   security_group_id = aws_security_group.k8s_nodes.id
 }
'''


def test_detects_the_real_suppression_diff_from_pugetscope():
    found = handler._find_added_suppressions(PUGETSCOPE_SUPPRESSION_DIFF)

    assert len(found) == 2
    assert all("tfsec:ignore" in line for line in found)


@pytest.mark.parametrize("marker", [
    "#tfsec:ignore:aws-ec2-no-public-ingress-sgr",
    "# trivy:ignore:AVD-AWS-0107",
    "#checkov:skip=CKV_AWS_18:reviewed",
    "# nosec",
])
def test_every_suppression_dialect_is_caught(marker):
    diff = f"--- a/main.tf\n+++ b/main.tf\n@@ -1 +1,2 @@\n {marker.upper()}\n+  {marker}\n"

    assert handler._find_added_suppressions(diff)


def test_preexisting_suppressions_are_not_the_agents_doing():
    """A suppression already in the file is the author's call. Only lines the
    fix adds are the agent's responsibility."""
    diff = (
        "--- a/main.tf\n+++ b/main.tf\n@@ -1,3 +1,3 @@\n"
        " #tfsec:ignore:aws-ec2-no-public-ingress-sgr\n"
        '-  cidr_blocks = ["0.0.0.0/0"]\n'
        '+  cidr_blocks = ["10.0.0.0/8"]\n'
    )

    assert handler._find_added_suppressions(diff) == []


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_suppressing_fix_is_rejected_before_it_is_ever_scanned(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The critical path. A suppression would pass the self-check by
    construction -- the rule stops firing and nothing new appears -- so it has
    to be refused before the scanner ever runs on it."""
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = {**next(f for f in before["findings"]
                      if f["rule_id"] == "AWS-0132"),
               "status": "mapped"}

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [finding]},           # _query_mapped_findings
        {"Items": before["findings"]},  # _chain_root's findings-on-file query
    ]
    mock_dynamodb.Table.return_value = mock_table

    original = _read_fixture_tf("s3-bucket-encryption", "before")
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: original.encode())}

    # The model "fixes" it by appending a suppression instead of encrypting.
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": original + "\n#tfsec:ignore:aws-s3-enable-bucket-encryption\n",
        "rationale": "Bucket holds only public assets, so encryption is unnecessary.",
    })

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)

    assert result["fix_proposed_count"] == 0
    assert result["needs_human_only_count"] == 1

    # Never scanned, never uploaded for scanning.
    mock_lambda_client.invoke.assert_not_called()
    mock_s3.put_object.assert_not_called()

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert written[":status"] == "needs-human-only"
    assert written[":pf"]["self_check_passed"] is False
    assert written[":pf"]["cleared"] is False
    assert written[":pf"]["suppression_attempt"]


# ---------- deletion gate ----------

# Reduced from PugetScope's modules/security_groups/main.tf.
SG_ORIGINAL = '''
resource "aws_security_group" "k8s_nodes" {
  name_prefix = "pugetscope-k8s-nodes-"
}

resource "aws_security_group_rule" "http_from_internet" {
  type        = "ingress"
  from_port   = 80
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "nodeport_from_internet" {
  type        = "ingress"
  from_port   = 30000
  cidr_blocks = ["0.0.0.0/0"]
}
'''


def test_deleting_a_resource_is_reported():
    """The real port-80 failure: the rule was removed outright, which scans
    clean because the thing that raised the finding is gone."""
    corrected = SG_ORIGINAL.replace('''resource "aws_security_group_rule" "http_from_internet" {
  type        = "ingress"
  from_port   = 80
  cidr_blocks = ["0.0.0.0/0"]
}
''', "# Plaintext HTTP is not exposed.\n")

    assert handler._find_dropped_resources(SG_ORIGINAL, corrected) == [
        "aws_security_group_rule.http_from_internet"
    ]


def test_renaming_a_resource_is_not_treated_as_a_deletion():
    """The real NodePort fix renamed nodeport_from_internet ->
    nodeport_from_admin while rescoping its CIDR. That is a delete plus an add
    in diff terms, but nothing was actually dropped."""
    corrected = SG_ORIGINAL.replace(
        '"nodeport_from_internet"', '"nodeport_from_admin"'
    ).replace('from_port   = 30000\n  cidr_blocks = ["0.0.0.0/0"]',
              'from_port   = 30000\n  cidr_blocks = var.admin_cidrs')

    assert handler._find_dropped_resources(SG_ORIGINAL, corrected) == []


def test_tightening_a_resource_in_place_is_not_a_deletion():
    corrected = SG_ORIGINAL.replace('cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = ["10.0.0.0/8"]')

    assert handler._find_dropped_resources(SG_ORIGINAL, corrected) == []


def test_adding_a_resource_is_not_a_deletion():
    corrected = SG_ORIGINAL + '\nresource "aws_flow_log" "vpc" {\n}\n'

    assert handler._find_dropped_resources(SG_ORIGINAL, corrected) == []


def _run_one_finding(mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client, payload,
                     scan_response=None):
    """Drives handler() over a single mapped finding with a canned model reply.

    scan_response overrides what the mocked iac-scanner returns for the
    self-check; it defaults to the fixture's captured clean-fix rescan."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = {**next(f for f in before["findings"]
                      if f["rule_id"] == "AWS-0132"),
               "status": "mapped"}

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [finding]},
        {"Items": before["findings"]},
    ]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response(payload)
    rescan = after if scan_response is None else scan_response
    mock_lambda_client.invoke.return_value = {
        "Payload": SimpleNamespace(read=lambda: json.dumps(rescan).encode())
    }

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)
    return result, mock_table


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_declared_assumptions_force_human_review_despite_a_clean_rescan(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The port-80 class of failure: the scanner is satisfied, but the fix
    rests on a claim about the wider system that nobody has checked."""
    result, mock_table = _run_one_finding(
        mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client,
        {
            "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
            "rationale": "Added a default SSE configuration.",
            "assumptions": ["Assumes certificate issuance does not use ACME HTTP-01."],
        },
    )

    assert result["fix_proposed_count"] == 0
    assert result["needs_human_only_count"] == 1

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert written[":status"] == "needs-human-only"
    assert written[":pf"]["self_check_passed"] is False
    assert written[":pf"]["assumptions"]
    # The rescan still ran and its verdict is preserved for the reviewer.
    assert written[":pf"]["cleared"] is True


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_no_assumptions_and_no_deletions_still_passes(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The gates must not swallow legitimately clean fixes."""
    result, mock_table = _run_one_finding(
        mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client,
        {
            "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
            "rationale": "Added a default SSE configuration.",
            "assumptions": [],
        },
    )

    assert result["fix_proposed_count"] == 1
    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert written[":status"] == "fix-proposed"
    assert written[":pf"]["self_check_passed"] is True
    assert written[":pf"]["dropped_resources"] == []
    assert written[":pf"]["assumptions"] == []


# ---------- unparseable-fix gate ----------

# The scanner's fixture, not a copy: this is the same artifact on both sides of
# the boundary -- iac-scanner's input and remediation-agent's output --
# and a duplicate would drift the moment either side edited its own.
UNPARSEABLE_TF = (
    Path(__file__).parents[1] / "iac-scanner" / "fixtures" / "unparseable" / "main.tf"
).read_text()


def test_an_empty_rescan_reads_as_a_cleared_finding():
    """Why the gate has to exist, pinned as a test rather than left in a
    comment. _evaluate_self_check cannot tell "the fix worked" from "the
    scanner returned nothing", and it is right not to try -- scoring the
    rescan is its job, deciding whether a rescan happened is not. Delete the
    gate and this is the behaviour that takes over."""
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0132")

    passed, new_findings, cleared = handler._evaluate_self_check(finding, [], _pairs(before))

    assert passed is True
    assert cleared is True
    assert new_findings == []


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_an_unparseable_fix_is_never_scored_as_a_pass(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The false pass, end to end. The model returns a file whose brace it
    dropped; the scanner parses nothing, so it reports nothing. Without the
    gate the test above shows exactly what happens next: fix-proposed, with a
    self-check badge on a file that is not valid Terraform."""
    result, mock_table = _run_one_finding(
        mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client,
        {
            "corrected_file_content": UNPARSEABLE_TF,
            "rationale": "Narrowed the SSH ingress CIDR to the VPC range.",
            "assumptions": [],
        },
        scan_response={"findings": [], "scan_errors": ["main.tf"]},
    )

    assert result["fix_proposed_count"] == 0
    assert result["needs_human_only_count"] == 1

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert written[":status"] == "needs-human-only"
    assert written[":pf"]["self_check_passed"] is False
    assert written[":pf"]["scan_errors"] == ["main.tf"]
    # Not "the fix missed the finding" -- nothing was checked at all, and the
    # reviewer needs those told apart.
    assert written[":pf"]["cleared"] is False
    # The diff is still written: a reviewer fixing the brace by hand wants to
    # see what the agent was attempting.
    assert written[":pf"]["diff"]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_scan_error_naming_another_path_still_blocks_the_verdict(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The self-check scratch prefix holds exactly one file, so any parse error
    the rescan reports is about the fix under test whatever path it names."""
    result, _ = _run_one_finding(
        mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client,
        {
            "corrected_file_content": UNPARSEABLE_TF,
            "rationale": "Narrowed the SSH ingress CIDR.",
            "assumptions": [],
        },
        scan_response={"findings": [], "scan_errors": ["modules/sg/main.tf"]},
    )

    assert result["fix_proposed_count"] == 0


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_scanner_crash_leaves_the_finding_for_a_retry(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """iac-scanner raising ScannerError surfaces as a FunctionError on
    the invoke. Nothing was learned about this fix, so the finding must not be
    written at all -- it stays "mapped" and a re-run picks it up again."""
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = {**next(f for f in before["findings"]
                      if f["rule_id"] == "AWS-0132"),
               "status": "mapped"}

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": [finding]}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
        "rationale": "Added a default SSE configuration.",
        "assumptions": [],
    })
    mock_lambda_client.invoke.return_value = {
        "FunctionError": "Unhandled",
        "Payload": SimpleNamespace(read=lambda: json.dumps(
            {"errorType": "ScannerError", "errorMessage": "trivy produced no output (exit 126)"}
        ).encode()),
    }

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)

    assert result["error_count"] == 1
    assert result["fix_proposed_count"] == 0
    assert result["needs_human_only_count"] == 0
    mock_table.update_item.assert_not_called()


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_response_without_scan_errors_is_not_treated_as_a_failure(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """Backwards compatibility with scanner responses predating the field --
    absent means "none reported", not "unknown, fail closed". Failing closed
    here would reject every fix until the scanner Lambda was redeployed.

    The fixtures were re-captured after the field existed, so the old shape
    is made here by dropping it."""
    after = {k: v for k, v in _load_fixture("s3-bucket-encryption", "after").items() if k != "scan_errors"}
    assert "scan_errors" not in after

    result, mock_table = _run_one_finding(
        mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client,
        {
            "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
            "rationale": "Added a default SSE configuration.",
            "assumptions": [],
        },
        scan_response=after,
    )

    assert result["fix_proposed_count"] == 1
    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert written[":pf"]["scan_errors"] == []


# ---------- _compute_diff ----------

def test_compute_diff_matches_fixture_after_content():
    before_content = _read_fixture_tf("s3-bucket-encryption", "before")
    after_content = _read_fixture_tf("s3-bucket-encryption", "after")

    diff_text = handler._compute_diff(before_content, after_content, "main.tf")

    assert "a/main.tf" in diff_text
    assert "b/main.tf" in diff_text
    assert "+resource \"aws_s3_bucket_server_side_encryption_configuration\" \"data\"" in diff_text


# ---------- handler() end to end ----------

def _fake_anthropic_response(payload_dict):
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(payload_dict))])


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_handler_marks_fix_proposed_on_clean_self_check(mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client):
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0132")
    finding = {**finding, "status": "mapped"}

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [finding]},          # _query_mapped_findings
        {"Items": before["findings"]}, # _query_baseline_pairs
    ]
    mock_dynamodb.Table.return_value = mock_table

    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }

    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
        "rationale": "Added a default SSE configuration for the bucket.",
    })

    mock_lambda_client.invoke.return_value = {
        "Payload": SimpleNamespace(read=lambda: json.dumps(after).encode())
    }

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)

    assert result == {
        "pr_id": "fixture-s3-enc-before",
        "fix_proposed_count": 1,
        "needs_human_only_count": 0,
        "superseded_count": 0,
        "error_count": 0,
        "remaining": 0,
    }

    mock_s3.put_object.assert_called_once()
    put_kwargs = mock_s3.put_object.call_args.kwargs
    assert put_kwargs["Key"] == f"fixes/fixture-s3-enc-before/{finding['finding_id']}/main.tf"

    mock_table.update_item.assert_called_once()
    update_kwargs = mock_table.update_item.call_args.kwargs
    assert update_kwargs["ExpressionAttributeValues"][":status"] == "fix-proposed"
    proposed_fix = update_kwargs["ExpressionAttributeValues"][":pf"]
    assert proposed_fix["self_check_passed"] is True
    assert proposed_fix["self_check_new_findings"] == []
    assert proposed_fix["cleared"] is True


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_handler_marks_needs_human_only_when_fix_does_not_clear_finding(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = next(f for f in before["findings"] if f["rule_id"] == "AWS-0132")
    finding = {**finding, "status": "mapped"}

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [finding]},
        {"Items": before["findings"]},
    ]
    mock_dynamodb.Table.return_value = mock_table

    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }

    # LLM "fix" that changes nothing meaningful -- self-check should catch it.
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "before"),
        "rationale": "No-op.",
    })

    # Rescan comes back identical to the original baseline.
    mock_lambda_client.invoke.return_value = {
        "Payload": SimpleNamespace(read=lambda: json.dumps(before).encode())
    }

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)

    assert result == {
        "pr_id": "fixture-s3-enc-before",
        "fix_proposed_count": 0,
        "needs_human_only_count": 1,
        "superseded_count": 0,
        "error_count": 0,
        "remaining": 0,
    }

    update_kwargs = mock_table.update_item.call_args.kwargs
    assert update_kwargs["ExpressionAttributeValues"][":status"] == "needs-human-only"
    assert update_kwargs["ExpressionAttributeValues"][":pf"]["self_check_passed"] is False
    assert update_kwargs["ExpressionAttributeValues"][":pf"]["cleared"] is False


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_handler_isolates_a_failing_finding_and_keeps_going(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """One finding blowing up must not abandon the rest of the file, and the
    failed finding must keep status "mapped" so a re-run retries it.

    The failure is injected into the model call rather than the snapshot read:
    the snapshot is now read once per file, so a failure there is the file's
    and takes every finding on it down (covered separately below)."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    pair = [
        {**next(f for f in before["findings"] if f["rule_id"] == "AWS-0132"),
         "status": "mapped"},
        {**next(f for f in before["findings"] if f["rule_id"] != "AWS-0132"),
         "status": "mapped"},
    ]
    # Remediation order is deterministic, so which one gets the failing call is
    # too -- derived here rather than assumed.
    first, second = sorted(pair, key=handler._remediation_order)

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": pair},               # _query_mapped_findings
        {"Items": before["findings"]}, # _chain_root's findings-on-file query
    ]
    mock_dynamodb.Table.return_value = mock_table

    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }

    mock_get_client.return_value.messages.create.side_effect = [
        RuntimeError("Anthropic 500"),
        _fake_anthropic_response({
            "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
            "rationale": "Added a default SSE configuration for the bucket.",
            "assumptions": [],
        }),
    ]
    mock_lambda_client.invoke.return_value = {
        "Payload": SimpleNamespace(read=lambda: json.dumps(after).encode())
    }

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)

    assert result == {
        "pr_id": "fixture-s3-enc-before",
        "fix_proposed_count": 1,
        "needs_human_only_count": 0,
        "superseded_count": 0,
        "error_count": 1,
        "remaining": 0,
    }
    # Only the surviving finding got written back -- the failed one is untouched.
    mock_table.update_item.assert_called_once()
    assert mock_table.update_item.call_args.kwargs["Key"]["sk"] == second["sk"]
    # The failed finding never joined the chain, so the survivor was still
    # drafted against the pristine file.
    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert written[":pf"]["applies_after"] == []
    assert first["sk"] != second["sk"]


# ---------- per-file chaining ----------

# Marks the fix the s3-bucket-encryption fixture applies. Present in after/,
# absent from before/ -- which matters because before/ is a literal substring
# of after/, so "is the base content in this prompt" cannot tell the two apart.
SSE_MARKER = "aws_s3_bucket_server_side_encryption_configuration"

LOGGING_RULE = "AWS-0089"

SUPPRESSION_LINE = "#tfsec:ignore:aws-s3-enable-bucket-encryption"


def _mapped(rule_id, line_start, finding_id, file="main.tf", source="trivy"):
    return {
        "pk": "PR#chain-1", "sk": f"FINDING#{finding_id}", "finding_id": finding_id,
        "file": file, "source": source, "rule_id": rule_id,
        "line_range": [line_start, line_start], "severity": "HIGH", "status": "mapped",
    }


def _scan_reply(scan_response):
    """One mocked iac-scanner invocation result."""
    body = json.dumps(scan_response).encode()
    return {"Payload": SimpleNamespace(read=lambda: body)}


def _prompt_of(mock_get_client, call_index):
    call = mock_get_client.return_value.messages.create.call_args_list[call_index]
    return call.kwargs["messages"][0]["content"]


def _written(mock_table, call_index):
    return mock_table.update_item.call_args_list[call_index].kwargs["ExpressionAttributeValues"]


def _encryption_then_logging():
    """Two findings on one file, in the order the chain will process them."""
    return sorted(
        [_mapped("AWS-0132", 1, "f1"),
         _mapped(LOGGING_RULE, 2, "f2")],
        key=handler._remediation_order,
    )


def test_findings_are_grouped_by_file_and_ordered_by_position():
    """The order fixes which fix each later fix is drafted on, so identical
    inputs must always produce the identical chain."""
    findings = [
        _mapped("c", 9, "f3"), _mapped("a", 1, "f1", file="b.tf"),
        _mapped("b", 2, "f2"), _mapped("d", 1, "f4"),
    ]

    grouped = list(handler._group_by_file(findings))

    assert [f for f, _ in grouped] == ["b.tf", "main.tf"]
    assert [g["finding_id"] for g in grouped[1][1]] == ["f4", "f2", "f3"]


def test_ordering_survives_a_null_line_range():
    """A rule that names a file rather than a line still has to sort somewhere
    deterministic instead of raising."""
    unpositioned = {**_mapped("x", None, "f9"), "line_range": [None, None]}

    assert handler._remediation_order(unpositioned)[0] == 0


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_each_fix_is_drafted_against_the_previous_accepted_fix(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The point of the change. Two findings on one file used to produce two
    whole-file rewrites of the same lines, both rooted at the pristine
    snapshot, so approving both was a guaranteed conflict."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    original = _read_fixture_tf("s3-bucket-encryption", "before")
    first_fix = _read_fixture_tf("s3-bucket-encryption", "after")
    second_fix = first_fix + '\nresource "aws_s3_bucket_logging" "added_second" {}\n'
    # What the scanner reports once the logging fix lands too.
    after_both = {"findings": [f for f in after["findings"] if f["rule_id"] != LOGGING_RULE]}

    pair = _encryption_then_logging()

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": pair}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: original.encode())}
    mock_get_client.return_value.messages.create.side_effect = [
        _fake_anthropic_response({"corrected_file_content": first_fix,
                                  "rationale": "Added SSE.", "assumptions": []}),
        _fake_anthropic_response({"corrected_file_content": second_fix,
                                  "rationale": "Added logging.", "assumptions": []}),
    ]
    mock_lambda_client.invoke.side_effect = [_scan_reply(after), _scan_reply(after_both)]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["fix_proposed_count"] == 2

    # The first call saw the pristine file; the second saw the first fix's
    # output. Checked by the marker rather than by substring, since before/ is
    # itself a substring of after/.
    assert SSE_MARKER not in _prompt_of(mock_get_client, 0)
    assert SSE_MARKER in _prompt_of(mock_get_client, 1)

    # And the second fix's diff is minimal against that base rather than
    # re-proposing the first fix's edit alongside its own.
    second_written = _written(mock_table, 1)
    assert "aws_s3_bucket_logging" in second_written[":pf"]["diff"]
    assert SSE_MARKER not in second_written[":pf"]["diff"]

    # The dependency is recorded, so a reviewer is not left to infer it --
    # and it carries a hash of the prerequisite's diff *as drafted*, which is
    # what lets review-api later tell an intact prerequisite from an edited
    # one without reconstructing any file content.
    assert _written(mock_table, 0)[":pf"]["applies_after"] == []
    assert second_written[":pf"]["applies_after"] == [{
        "finding_id": pair[0]["finding_id"],
        "diff_sha256": hashlib.sha256(
            _written(mock_table, 0)[":pf"]["diff"].encode("utf-8")
        ).hexdigest(),
    }]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_rejected_fix_does_not_become_the_base_for_the_next(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """A suppression is refused before it is ever scanned, so it was never
    shown to be a sound edit. Building on it would carry the suppression into
    every later diff in the file."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    original = _read_fixture_tf("s3-bucket-encryption", "before")

    pair = _encryption_then_logging()

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": pair}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: original.encode())}
    mock_get_client.return_value.messages.create.side_effect = [
        _fake_anthropic_response({
            "corrected_file_content": original + "\n#tfsec:ignore:aws-s3-enable-bucket-encryption\n",
            "rationale": "Intentional.", "assumptions": []}),
        _fake_anthropic_response({
            "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
            "rationale": "Added SSE.", "assumptions": []}),
    ]
    # Only the second finding reaches the scanner; the first is refused before it.
    mock_lambda_client.invoke.side_effect = [_scan_reply(after)]

    handler.handler({"pr_id": "chain-1"}, None)

    # The prompt text itself forbids suppressions by name, so the marker has to
    # be the specific directive the rejected fix added, not the bare tool name.
    assert SUPPRESSION_LINE not in _prompt_of(mock_get_client, 1)
    assert _written(mock_table, 1)[":pf"]["applies_after"] == []


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_fix_held_for_human_review_still_advances_the_chain(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The two verdicts come apart here. A fix carrying an assumption is
    needs-human-only, but the rescan proved it cleared its finding without
    introducing new ones, so it is a sound edit to build on. Gating the chain
    on the written verdict instead would return the rest of the file to
    colliding rewrites over one declared assumption."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    original = _read_fixture_tf("s3-bucket-encryption", "before")
    first_fix = _read_fixture_tf("s3-bucket-encryption", "after")
    after_both = {"findings": [f for f in after["findings"] if f["rule_id"] != LOGGING_RULE]}

    pair = _encryption_then_logging()

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": pair}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: original.encode())}
    mock_get_client.return_value.messages.create.side_effect = [
        _fake_anthropic_response({
            "corrected_file_content": first_fix, "rationale": "Added SSE.",
            "assumptions": ["Assumes no client requires an unencrypted read path."]}),
        _fake_anthropic_response({
            "corrected_file_content": first_fix + '\nresource "aws_s3_bucket_logging" "l" {}\n',
            "rationale": "Added logging.", "assumptions": []}),
    ]
    mock_lambda_client.invoke.side_effect = [_scan_reply(after), _scan_reply(after_both)]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["needs_human_only_count"] == 1
    assert result["fix_proposed_count"] == 1
    assert SSE_MARKER in _prompt_of(mock_get_client, 1)
    assert _written(mock_table, 1)[":pf"]["applies_after"] == [{
        "finding_id": pair[0]["finding_id"],
        "diff_sha256": hashlib.sha256(
            _written(mock_table, 0)[":pf"]["diff"].encode("utf-8")
        ).hexdigest(),
    }]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_an_unreadable_snapshot_fails_every_finding_on_that_file(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The snapshot is read once per file now, so its failure belongs to the
    file rather than to any one finding. All of them stay "mapped"."""
    pair = [_mapped("a", 1, "f1"), _mapped("b", 2, "f2")]

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": pair}, {"Items": []}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.side_effect = RuntimeError("NoSuchKey")

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["error_count"] == 2
    assert result["fix_proposed_count"] == 0
    assert result["needs_human_only_count"] == 0
    mock_table.update_item.assert_not_called()
    mock_get_client.assert_not_called()


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_finding_an_earlier_fix_already_cleared_is_marked_superseded(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """Rules overlap, so one fix routinely clears more than its own finding.

    Chaining the baseline made that case score as a failure: the second
    finding's rule is already at 0 in the baseline, its rescan is also 0, and
    cleared is `rescan < baseline` -- `0 < 0` is False. A finding that is
    genuinely resolved would have been written up as a fix that failed to
    clear it, which is the opposite of the truth."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    original = _read_fixture_tf("s3-bucket-encryption", "before")
    first_fix = _read_fixture_tf("s3-bucket-encryption", "after")
    # The first fix clears the logging rule as well as its own.
    clears_both = {"findings": [f for f in after["findings"] if f["rule_id"] != LOGGING_RULE]}

    pair = _encryption_then_logging()

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": pair}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: original.encode())}
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response(
        {"corrected_file_content": first_fix, "rationale": "Added SSE.", "assumptions": []}
    )
    mock_lambda_client.invoke.side_effect = [_scan_reply(clears_both)]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["fix_proposed_count"] == 1
    assert result["superseded_count"] == 1
    # The regression: this must not be counted as a fix that failed.
    assert result["needs_human_only_count"] == 0

    # No second model call and no second scan -- there was nothing left to fix.
    assert mock_get_client.return_value.messages.create.call_count == 1
    assert mock_lambda_client.invoke.call_count == 1

    superseded = mock_table.update_item.call_args_list[1].kwargs
    assert superseded["Key"]["sk"] == pair[1]["sk"]
    values = superseded["ExpressionAttributeValues"]
    assert values[":status"] == "superseded"
    assert values[":by"] == pair[0]["finding_id"]
    # No proposed_fix is written: none was drafted, and its absence is what
    # makes review-api refuse an approve or edit here.
    assert ":pf" not in values


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_partially_cleared_rule_does_not_supersede(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """Only a rule taken to zero supersedes. A file can hold several instances
    of one rule, and clearing one of three leaves the others firing -- that
    finding still needs its own fix."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    original = _read_fixture_tf("s3-bucket-encryption", "before")
    first_fix = _read_fixture_tf("s3-bucket-encryption", "after")
    # Logging still fires after the first fix, so nothing is superseded.
    still_logging = after

    pair = _encryption_then_logging()

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": pair}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: original.encode())}
    mock_get_client.return_value.messages.create.side_effect = [
        _fake_anthropic_response({"corrected_file_content": first_fix,
                                  "rationale": "Added SSE.", "assumptions": []}),
        _fake_anthropic_response({"corrected_file_content": first_fix + '\nresource "aws_s3_bucket_logging" "l" {}\n',
                                  "rationale": "Added logging.", "assumptions": []}),
    ]
    mock_lambda_client.invoke.side_effect = [
        _scan_reply(still_logging),
        _scan_reply({"findings": [f for f in after["findings"] if f["rule_id"] != LOGGING_RULE]}),
    ]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["superseded_count"] == 0
    assert result["fix_proposed_count"] == 2
    assert mock_get_client.return_value.messages.create.call_count == 2


# ---------- chain root: where a file's chain starts ----------

ACCEPTED_DIFF = "--- a/main.tf\n+++ b/main.tf\n@@ -1 +1 @@\n-old\n+accepted\n"
ACCEPTED_CONTENT = "accepted\n"


def _accepted(finding_id, applies_after=(), status="resolved"):
    return {
        **_mapped("AWS-0132", 1, finding_id),
        "status": status,
        "proposed_fix": {"diff": ACCEPTED_DIFF, "applies_after": list(applies_after)},
    }


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_chain_roots_at_the_last_accepted_fix_not_the_snapshot(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """After a reviewer accepts f1, a reopened f2 returned to mapped must be
    redrafted on top of f1's content -- the edited content, if it was edited.
    Rooting at the snapshot would redraft f2 against a file with no f1 in it,
    and it would collide with f1 on application: the original problem."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    accepted = _accepted("f1")
    to_redraft = _mapped(LOGGING_RULE, 2, "f2")

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [to_redraft]},                              # mapped
        {"Items": before["findings"] + [accepted, to_redraft]},  # on file
    ]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: ACCEPTED_CONTENT.encode())}
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": ACCEPTED_CONTENT + 'resource "aws_s3_bucket_logging" "l" {}\n',
        "rationale": "Added logging.", "assumptions": [],
    })
    after_both = {"findings": [f for f in after["findings"] if f["rule_id"] != LOGGING_RULE]}
    mock_lambda_client.invoke.side_effect = [
        _scan_reply(after),        # rescan of the accepted root
        _scan_reply(after_both),   # self-check of f2's redraft
    ]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["fix_proposed_count"] == 1
    # The base was read from the accepted fix's content, not the snapshot.
    assert "fixes/chain-1/f1/main.tf" in [
        c.kwargs["Key"] for c in mock_s3.get_object.call_args_list
    ]  # the pristine file is also read, for the finding's flagged lines
    assert ACCEPTED_CONTENT in _prompt_of(mock_get_client, 0)
    # The root was rescanned to get its counts, then the redraft self-checked.
    assert mock_lambda_client.invoke.call_count == 2
    # And the redraft records the accepted fix as what it is built on.
    written = _written(mock_table, 0)
    assert written[":pf"]["applies_after"] == [
        {"finding_id": "f1", "diff_sha256": handler._diff_sha256(ACCEPTED_DIFF)}
    ]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_rejected_fix_is_not_a_root(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """A rejection now sets needs-human-only, so status is enough to say a
    fix is not landing. The chain starts from the snapshot as if the fix had
    never been drafted -- which is what "the chain without that fix" means."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    rejected = _accepted("f1", status="needs-human-only")
    to_redraft = _mapped("AWS-0132", 1, "f2")
    original = _read_fixture_tf("s3-bucket-encryption", "before")

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [to_redraft]},
        {"Items": before["findings"] + [rejected, to_redraft]},
    ]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: original.encode())}
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
        "rationale": "Added SSE.", "assumptions": [],
    })
    mock_lambda_client.invoke.side_effect = [_scan_reply(after)]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["fix_proposed_count"] == 1
    assert mock_s3.get_object.call_args.kwargs["Key"] == "scans/chain-1/main.tf"
    assert _written(mock_table, 0)[":pf"]["applies_after"] == []
    # No root rescan: the snapshot's counts are already in the table.
    assert mock_lambda_client.invoke.call_count == 1


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_rule_the_accepted_root_already_cleared_is_superseded_by_it(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """cleared_by only knows about fixes drafted in this run. A rule the
    accepted chain already took to zero has to be recognised from the root's
    counts, or the finding is drafted anyway -- and it was, live: the model
    returned the file unchanged saying the rule was already satisfied, and
    the empty diff scored `cleared=False`. Two model calls, two findings
    marked as failed fixes that were in fact resolved."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    accepted = _accepted("f1")
    # The accepted fix cleared encryption. This finding is on that very rule,
    # reopened to mapped (its superseder was edited) and back for a fix.
    already_cleared = _mapped("AWS-0132", 1, "s1")

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [already_cleared]},
        {"Items": before["findings"] + [accepted, already_cleared]},
    ]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: ACCEPTED_CONTENT.encode())}
    # The root's rescan: encryption is gone.
    mock_lambda_client.invoke.side_effect = [_scan_reply(after)]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["superseded_count"] == 1
    assert result["needs_human_only_count"] == 0
    # Never drafted, never self-checked.
    mock_get_client.return_value.messages.create.assert_not_called()
    assert mock_lambda_client.invoke.call_count == 1
    values = _written(mock_table, 0)
    assert values[":status"] == "superseded"
    assert values[":by"] == "f1"


def test_the_root_is_the_accepted_fix_with_the_longest_chain():
    """applies_after is cumulative, so the longest chain has every other
    accepted fix already applied. Anything else would drop a fix."""
    with patch.object(handler, "dynamodb") as mock_dynamodb, \
            patch.object(handler, "s3") as mock_s3, \
            patch.object(handler, "_invoke_self_check", return_value=([], [])):
        mock_table = MagicMock()
        mock_table.query.return_value = {"Items": [
            _accepted("f1"),
            _accepted("f3", applies_after=[{"finding_id": "f1"}, {"finding_id": "f2"}]),
            _accepted("f2", applies_after=[{"finding_id": "f1"}]),
        ]}
        mock_dynamodb.Table.return_value = mock_table
        mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: b"x")}

        _, _, chain = handler._chain_root("chain-1", "main.tf")

    assert [c["finding_id"] for c in chain] == ["f1", "f2", "f3"]
    assert mock_s3.get_object.call_args.kwargs["Key"] == "fixes/chain-1/f3/main.tf"


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_an_accepted_fix_that_does_not_parse_fails_the_whole_file(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """A reviewer's edit can break the syntax, and it is now the base. Nothing
    can be drafted on a file the scanner cannot read, so every mapped finding
    on it errors out and stays mapped, rather than being drafted against a
    base that yields zero findings and scores everything as cleared."""
    before = _load_fixture("s3-bucket-encryption", "before")
    to_redraft = [_mapped("a", 1, "f2"), _mapped("b", 2, "f3")]

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": to_redraft},
        {"Items": before["findings"] + [_accepted("f1")] + to_redraft},
    ]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: b"broken {")}
    mock_lambda_client.invoke.side_effect = [_scan_reply({"findings": [], "scan_errors": ["main.tf"]})]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["error_count"] == 2
    assert result["fix_proposed_count"] == 0
    mock_get_client.assert_not_called()
    mock_table.update_item.assert_not_called()


# ---------- pagination ----------

def test_query_all_follows_last_evaluated_key():
    """DynamoDB applies FilterExpression after the 1MB read cap, so a page can
    come back nearly empty with more matches still pending."""
    table = MagicMock()
    table.query.side_effect = [
        {"Items": [{"n": 1}], "LastEvaluatedKey": {"pk": "PR#x", "sk": "FINDING#a"}},
        {"Items": [{"n": 2}, {"n": 3}]},
    ]

    items = handler._query_all(table, KeyConditionExpression="pk = :pk")

    assert items == [{"n": 1}, {"n": 2}, {"n": 3}]
    assert table.query.call_count == 2
    assert table.query.call_args.kwargs["ExclusiveStartKey"] == {"pk": "PR#x", "sk": "FINDING#a"}


# ---------- one file per invocation, and continuing a file across invocations ----------
#
# The pipeline's Map state (terraform/step_functions.tf) invokes the handler
# once per file, and a file with more findings than fit in one invocation is
# continued by feeding the output back in as the next input.

def _context(*remaining_ms):
    """A Lambda context whose clock reads each value in turn, then the last one."""
    ctx = MagicMock()
    ctx.get_remaining_time_in_millis.side_effect = list(remaining_ms) + [remaining_ms[-1]] * 50
    return ctx


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_file_can_be_remediated_on_its_own(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """`file` narrows the mapped-findings query to that file, so the Map
    state's iterations never touch each other's files, and the answer names
    the file so the state machine's output is readable per iteration."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = _mapped("AWS-0132", 1, "f1")

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": [finding]}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
        "rationale": "Added SSE.", "assumptions": [],
    })
    mock_lambda_client.invoke.return_value = _scan_reply(after)

    result = handler.handler({"pr_id": "chain-1", "file": "main.tf"}, None)

    mapped_query = mock_table.query.call_args_list[0].kwargs
    assert "#file = :file" in mapped_query["FilterExpression"]
    assert mapped_query["ExpressionAttributeValues"][":file"] == "main.tf"
    assert result["file"] == "main.tf"
    assert result["fix_proposed_count"] == 1
    assert result["remaining"] == 0
    assert "resume_from" not in result


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_yields_before_the_clock_runs_out_and_says_where_to_resume(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """Being killed by the timeout mid-finding loses the model call in flight
    and, worse, returns nothing -- so the caller cannot tell where the chain
    got to. Stopping *before* a finding costs nothing, and the answer carries
    everything the next invocation needs."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    pair = _encryption_then_logging()

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": pair}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
        "rationale": "Added SSE.", "assumptions": [],
    })
    mock_lambda_client.invoke.return_value = _scan_reply(after)

    # Plenty of time for the first finding, not enough for a second.
    plenty = handler.FINDING_TIME_RESERVE_MS * 2
    result = handler.handler(
        {"pr_id": "chain-1", "file": "main.tf"}, _context(plenty, handler.FINDING_TIME_RESERVE_MS - 1),
    )

    assert mock_get_client.return_value.messages.create.call_count == 1
    assert result["fix_proposed_count"] == 1
    assert result["remaining"] == 1
    # The chain resumes at the fix that was verified, not at the snapshot.
    assert result["resume_from"] == pair[0]["finding_id"]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_continuation_roots_at_the_fix_it_was_told_to(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """The previous invocation's output, fed back in. f1 is fix-proposed --
    not accepted, nobody has reviewed it yet -- and the chain still roots at
    it, because restarting from the snapshot would draft f2 as a competing
    rewrite of the lines f1 just changed. The counts carry over too, so the
    file's total is reported rather than this invocation's share."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    drafted = _accepted("f1", status="fix-proposed")
    to_continue = _mapped(LOGGING_RULE, 2, "f2")

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [to_continue]},                                # mapped, on this file
        {"Items": before["findings"] + [drafted, to_continue]},  # on file
    ]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: ACCEPTED_CONTENT.encode())}
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": ACCEPTED_CONTENT + 'resource "aws_s3_bucket_logging" "l" {}\n',
        "rationale": "Added logging.", "assumptions": [],
    })
    after_both = {"findings": [f for f in after["findings"] if f["rule_id"] != LOGGING_RULE]}
    mock_lambda_client.invoke.side_effect = [
        _scan_reply(after),        # rescan of the resumed root
        _scan_reply(after_both),   # self-check of f2
    ]

    result = handler.handler({
        "pr_id": "chain-1", "file": "main.tf", "resume_from": "f1", "remaining": 1,
        "fix_proposed_count": 1, "needs_human_only_count": 0,
        "superseded_count": 0, "error_count": 0,
    }, None)

    assert "fixes/chain-1/f1/main.tf" in [
        c.kwargs["Key"] for c in mock_s3.get_object.call_args_list
    ]  # the pristine file is also read, for the finding's flagged lines
    assert ACCEPTED_CONTENT in _prompt_of(mock_get_client, 0)
    assert _written(mock_table, 0)[":pf"]["applies_after"] == [
        {"finding_id": "f1", "diff_sha256": handler._diff_sha256(ACCEPTED_DIFF)}
    ]
    assert result["fix_proposed_count"] == 2
    assert result["remaining"] == 0
    assert "resume_from" not in result


@patch.object(handler, "dynamodb")
def test_a_continuation_names_a_fix_that_was_never_drafted(mock_dynamodb):
    """A resume point that is not a drafted fix on the file has no content to
    root at. Failing the file is right: drafting against the snapshot instead
    would silently produce the competing rewrites the chain exists to avoid."""
    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [_mapped(LOGGING_RULE, 2, "f2")]},
        {"Items": [_mapped(LOGGING_RULE, 2, "f2")]},   # no f1 on the file
    ]
    mock_dynamodb.Table.return_value = mock_table

    result = handler.handler({"pr_id": "chain-1", "file": "main.tf", "resume_from": "f1"}, None)

    assert result["error_count"] == 1
    assert result["remaining"] == 0


def test_resume_from_needs_a_file():
    with pytest.raises(ValueError):
        handler.handler({"pr_id": "chain-1", "resume_from": "f1"}, None)


# ---------- questions: asking the repository instead of assuming ----------
#
# docs/context-agent-spec.md. The model may return `questions`; context-agent
# answers them with citations; the fix is redrafted knowing the answers.

QUESTION = "Does anything in this repository serve the bucket `data` anonymously?"


def _answered(answer, explanation="A CloudFront origin reads it with OAC.", citations=None):
    return {"question": QUESTION, "answer": answer, "explanation": explanation,
            "citations": citations if citations is not None else
            [{"file": "cdn.tf", "line_range": [12, 18], "excerpt": "origin_access_control_id ="}]}


def _questions_run(mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client, monkeypatch,
                   first_reply, context_reply, second_reply):
    monkeypatch.setattr(handler, "CONTEXT_AGENT_FUNCTION_NAME", "ctx-fn")
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = {**next(f for f in before["findings"] if f["rule_id"] == "AWS-0132"), "status": "mapped"}
    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": [finding]}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }
    mock_get_client.return_value.messages.create.side_effect = [
        _fake_anthropic_response(first_reply), _fake_anthropic_response(second_reply),
    ]
    mock_lambda_client.invoke.side_effect = [
        {"Payload": SimpleNamespace(read=lambda: json.dumps({"answers": context_reply}).encode())},
        _scan_reply(after),
    ]
    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)
    return result, mock_table


def _fix_reply(**overrides):
    reply = {
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
        "rationale": "Encrypted with KMS.", "assumptions": [], "questions": [],
    }
    reply.update(overrides)
    return reply


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_question_is_answered_and_the_fix_is_redrafted_on_the_answer(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client, monkeypatch
):
    """The point of the component. The first draft asked; context-agent was
    invoked with exactly that question; the second draft saw the cited
    answer; the answered question is not an assumption, so the fix passes."""
    result, mock_table = _questions_run(
        mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client, monkeypatch,
        first_reply=_fix_reply(questions=[QUESTION], assumptions=[]),
        context_reply=[_answered("no")],
        second_reply=_fix_reply(),
    )

    # context-agent got the question, before the self-check scan.
    ctx_call = mock_lambda_client.invoke.call_args_list[0].kwargs
    assert ctx_call["FunctionName"] == "ctx-fn"
    assert json.loads(ctx_call["Payload"]) == {
        "pr_id": "fixture-s3-enc-before", "s3_prefix": "scans/fixture-s3-enc-before/",
        "questions": [QUESTION],
    }
    # The redraft saw the answer and its citation, verbatim.
    redraft_prompt = _prompt_of(mock_get_client, 1)
    assert f"Q: {QUESTION}" in redraft_prompt
    assert "A: no -- A CloudFront origin reads it with OAC." in redraft_prompt
    assert "[cdn.tf:12-18] origin_access_control_id =" in redraft_prompt
    assert "Draft the fix knowing this" in redraft_prompt
    # And the first draft was asked to consider questions at all.
    assert "put it in `questions`" in _prompt_of(mock_get_client, 0)

    assert result["fix_proposed_count"] == 1
    written = _written(mock_table, 0)
    assert written[":status"] == "fix-proposed"
    assert written[":pf"]["assumptions"] == []
    assert written[":pf"]["questions"] == [_answered("no")]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_an_unknown_answer_holds_the_fix_without_becoming_an_assumption(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client, monkeypatch
):
    """'We looked and the repository does not say' is still something the
    fix may rest on, so it holds the fix like an assumption does -- but from
    the questions record, where it reads as what it is. It is not copied
    into assumptions as a question-shaped fact, even when the redraft did
    not restate it as a claim."""
    result, mock_table = _questions_run(
        mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client, monkeypatch,
        first_reply=_fix_reply(questions=[QUESTION]),
        context_reply=[_answered("unknown", "Nothing in the snapshot references the bucket.", citations=[])],
        second_reply=_fix_reply(),  # the redraft did not carry it as an assumption
    )

    assert result["needs_human_only_count"] == 1
    written = _written(mock_table, 0)
    assert written[":status"] == "needs-human-only"
    assert written[":pf"]["assumptions"] == []
    assert written[":pf"]["questions"][0]["answer"] == "unknown"
    assert written[":pf"]["cleared"] is True  # the scanner was satisfied; the hold is the gate


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_without_a_context_agent_questions_are_recorded_unanswered_and_hold(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client, monkeypatch
):
    """CONTEXT_AGENT_FUNCTION_NAME unset: one model call as before, no
    invoke, and anything the model wanted to ask is an assumption."""
    monkeypatch.setattr(handler, "CONTEXT_AGENT_FUNCTION_NAME", None)

    result, mock_table = _run_one_finding(
        mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client,
        _fix_reply(questions=[QUESTION]),
    )

    assert mock_get_client.return_value.messages.create.call_count == 1
    assert "Return an empty `questions` list." in _prompt_of(mock_get_client, 0)
    # The only invoke was the self-check scan.
    assert mock_lambda_client.invoke.call_count == 1
    assert result["needs_human_only_count"] == 1
    # Recorded as asked and unanswered, with the reason; not as an assumption.
    assert _written(mock_table, 0)[":pf"]["assumptions"] == []
    [q] = _written(mock_table, 0)[":pf"]["questions"]
    assert q["question"] == QUESTION and q["answer"] == "unknown"
    assert "No context-agent" in q["explanation"]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_failed_context_lookup_leaves_the_finding_for_a_retry(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client, monkeypatch
):
    """Drafting on an answer that was never given is worse than not drafting."""
    monkeypatch.setattr(handler, "CONTEXT_AGENT_FUNCTION_NAME", "ctx-fn")
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = {**next(f for f in before["findings"] if f["rule_id"] == "AWS-0132"), "status": "mapped"}
    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": [finding]}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response(
        _fix_reply(questions=[QUESTION])
    )
    mock_lambda_client.invoke.return_value = {
        "FunctionError": "Unhandled",
        "Payload": SimpleNamespace(read=lambda: b'{"errorType": "RuntimeError"}'),
    }

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)

    assert result["error_count"] == 1
    mock_table.update_item.assert_not_called()


# ---------- line drift: a finding's lines vs the chain's content ----------
#
# Observed on pugetscope-ctx-2: the first fix on the file inserted a locals
# block near the top, and every later finding -- whose line_range is from the
# pristine snapshot -- was drafted against lines that had moved. "Line 48"
# (port 80) pointed into the 6443 rule, and that is what got fixed.

DRIFT_ORIGINAL = "\n".join(f"line {n}" for n in range(1, 21)) + "\n"


def test_flagged_lines_are_taken_from_the_original_with_their_numbers():
    finding = _mapped("r", 10, "f1")
    finding["line_range"] = [10, 11]

    out = handler._flagged_lines(DRIFT_ORIGINAL, finding)

    assert out.splitlines() == ["8: line 8", "9: line 9", "10: line 10", "11: line 11",
                                "12: line 12", "13: line 13"]


def test_flagged_lines_clip_to_the_file_and_tolerate_a_missing_end():
    finding = _mapped("r", 1, "f1")
    finding["line_range"] = [1, None]

    assert handler._flagged_lines(DRIFT_ORIGINAL, finding).splitlines() == [
        "1: line 1", "2: line 2", "3: line 3",
    ]


def test_flagged_lines_are_empty_without_a_line_or_past_the_end():
    no_line = {**_mapped("r", None, "f1"), "line_range": [None, None]}
    past_end = {**_mapped("r", 99, "f1"), "line_range": [99, 99]}

    assert handler._flagged_lines(DRIFT_ORIGINAL, no_line) == ""
    assert handler._flagged_lines(DRIFT_ORIGINAL, past_end) == ""


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_draft_on_a_shifted_base_is_shown_the_original_lines(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    """Two findings on one file. The first fix prepends a block, so the
    second finding's line numbers no longer point at its rule in the base
    the second draft is given. That draft's prompt must carry the flagged
    lines as they were, numbered as the scanner numbered them, and say the
    file may have moved."""
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    original = _read_fixture_tf("s3-bucket-encryption", "before")
    # The first fix inserts three lines at the top of the file.
    first_fix = 'locals {\n  x = 1\n}\n' + _read_fixture_tf("s3-bucket-encryption", "after")
    second_fix = first_fix + '\nresource "aws_s3_bucket_logging" "l" {}\n'
    after_both = {"findings": [f for f in after["findings"] if f["rule_id"] != LOGGING_RULE]}
    pair = _encryption_then_logging()
    pair[1]["line_range"] = [2, 3]  # the logging finding, at its pristine lines

    mock_table = MagicMock()
    mock_table.query.side_effect = [{"Items": pair}, {"Items": before["findings"]}]
    mock_dynamodb.Table.return_value = mock_table
    mock_s3.get_object.return_value = {"Body": SimpleNamespace(read=lambda: original.encode())}
    mock_get_client.return_value.messages.create.side_effect = [
        _fake_anthropic_response({"corrected_file_content": first_fix, "rationale": "SSE.", "assumptions": [], "questions": []}),
        _fake_anthropic_response({"corrected_file_content": second_fix, "rationale": "Logging.", "assumptions": [], "questions": []}),
    ]
    mock_lambda_client.invoke.side_effect = [_scan_reply(after), _scan_reply(after_both)]

    result = handler.handler({"pr_id": "chain-1"}, None)

    assert result["fix_proposed_count"] == 2
    second_prompt = _prompt_of(mock_get_client, 1)
    original_lines = original.splitlines()
    # The pristine lines 2-3, numbered as the scanner numbered them ...
    assert f"2: {original_lines[1]}" in second_prompt
    assert f"3: {original_lines[2]}" in second_prompt
    # ... with the instruction, and against the shifted base.
    assert "lines may have moved" in second_prompt
    assert "Locate that configuration in the file below by its content" in second_prompt
    assert "locals {" in second_prompt
