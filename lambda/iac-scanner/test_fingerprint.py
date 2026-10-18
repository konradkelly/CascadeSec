"""The line-independent fingerprint (integrations-spec §3.2): what it is
anchored on, and that it does not move when lines do.

The resource values below are real ones, from a scan of the eval cases on
2026-10-18: Trivy names a CloudFormation resource by its line range, KICS
says "n/a" when it has none, and Trivy names no Kubernetes resource at all.
"""

from unittest.mock import MagicMock, patch

import pytest

import handler


def finding(resource="", line_range=(5, 8), file="main.tf", source="trivy", rule_id="AWS-0086"):
    return {"source": source, "rule_id": rule_id, "file": file, "resource": resource,
            "line_range": list(line_range), "finding_id": "x"}


@pytest.mark.parametrize("resource,usable", [
    ("aws_s3_bucket.logs", True),
    ("Deployment.app.caps", True),
    ("Microsoft.KeyVault/vaults.kv-eval-nopurge", True),
    ("${AWS::StackName}-trail", True),
    ("bucket-2", True),               # a name that ends in a digit is still a name
    ("template.yaml:5-8", False),     # Trivy on CloudFormation: a position
    ("template.yaml:12", False),
    ("n/a", False),                   # KICS's placeholder
    ("", False),                      # Trivy on Kubernetes
])
def test_only_a_name_anchors_the_fingerprint(resource, usable):
    assert (handler._anchor_resource(resource) is not None) is usable


def test_a_named_resource_ignores_where_its_lines_are():
    assert (handler._fingerprint(finding("aws_s3_bucket.logs", (5, 8)), "")
            == handler._fingerprint(finding("aws_s3_bucket.logs", (40, 43)), ""))


def test_a_positional_resource_falls_back_to_the_line_text():
    """Anchored on "template.yaml:5-8" it would change when a line is added
    above; anchored on the flagged line's text it does not."""
    before = handler._fingerprint(finding("template.yaml:5-8", (5, 8)), "  TrailBucket:")
    after = handler._fingerprint(finding("template.yaml:6-9", (6, 9)), "  TrailBucket:")
    assert before == after


def test_line_text_is_compared_without_surrounding_whitespace():
    assert (handler._fingerprint(finding(), "    privileged: true")
            == handler._fingerprint(finding(), "privileged: true\t"))


@pytest.mark.parametrize("change", [
    {"rule_id": "AWS-0087"}, {"source": "checkov"}, {"file": "other.tf"}, {"resource": "aws_s3_bucket.data"},
])
def test_anything_but_position_is_a_different_fingerprint(change):
    base = finding("aws_s3_bucket.logs")
    assert handler._fingerprint({**base, **change}, "") != handler._fingerprint(base, "")


def test_it_is_not_the_finding_id():
    """Review state stays on finding_id; the fingerprint sits beside it."""
    f = finding("aws_s3_bucket.logs")
    f["fingerprint"] = handler._fingerprint(f, "")
    assert f["fingerprint"] != f["finding_id"] and len(f["fingerprint"]) == 16


def test_add_fingerprints_reads_the_flagged_line(tmp_path):
    (tmp_path / "pod.yaml").write_text("apiVersion: v1\nkind: Pod\nspec:\n  privileged: true\n")
    shifted = tmp_path / "shifted"
    shifted.mkdir()
    (shifted / "pod.yaml").write_text("\n" + (tmp_path / "pod.yaml").read_text())
    a = [finding("", (4, 4), file="pod.yaml", rule_id="KSV-0017")]
    b = [finding("", (5, 5), file="pod.yaml", rule_id="KSV-0017")]

    handler._add_fingerprints(a, str(tmp_path))
    handler._add_fingerprints(b, str(shifted))

    assert a[0]["fingerprint"] == b[0]["fingerprint"]


def test_a_finding_with_no_line_or_file_still_gets_one(tmp_path):
    f = [finding("", (None, None), file="missing.yaml")]
    handler._add_fingerprints(f, str(tmp_path))
    assert len(f[0]["fingerprint"]) == 16


def test_the_fingerprint_is_stored_and_refreshed_by_every_scan():
    table = MagicMock()
    f = {"pk": "PR#p", "sk": "FINDING#a", "finding_id": "a", "target_type": "terraform",
         "finding_class": "misconfiguration", "source": "trivy", "rule_id": "AWS-0086", "file": "main.tf",
         "line_range": [1, 2], "severity": "HIGH", "resource": "aws_s3_bucket.b", "fingerprint": "f" * 16}
    with patch.object(handler, "dynamodb") as dynamodb, \
            patch.object(handler, "_existing_findings", return_value={}):
        dynamodb.Table.return_value = table
        handler._write_findings("p", [f])

    call = next(c for c in table.update_item.call_args_list if c.kwargs["Key"]["sk"] == "FINDING#a")
    assert "fingerprint = :fingerprint" in call.kwargs["UpdateExpression"]
    assert "if_not_exists(fingerprint" not in call.kwargs["UpdateExpression"]
    assert call.kwargs["ExpressionAttributeValues"][":fingerprint"] == "f" * 16
