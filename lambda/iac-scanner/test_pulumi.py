import json
from unittest.mock import MagicMock

import pytest

import handler


def plan():
    return {"planned_values": {"root_module": {"resources": []}},
            "configuration": {"root_module": {"resources": []}},
            "cascade_pulumi": {"mode": "mock", "sources": {
                "aws_s3_bucket.logs": {"urn": "urn:pulumi:test", "source": {"file": "infra/index.ts", "line": 5}}}}}


def test_download_admits_generated_plan_and_classifies_pulumi(tmp_path, monkeypatch):
    s3 = MagicMock()
    s3.get_paginator.return_value.paginate.return_value = [{"Contents": [{"Key": "scans/x/a.pulumi.plan.json"}]}]
    s3.download_file.side_effect = lambda _bucket, _key, dest: __import__("pathlib").Path(dest).write_text(json.dumps(plan()))
    monkeypatch.setattr(handler, "s3", s3)
    files, errors, types = handler._download_snapshot("bucket", "scans/x/", str(tmp_path))
    assert len(files) == 1 and not errors and types == {"a.pulumi.plan.json": "pulumi"}


def test_malformed_plan_is_reported_and_removed(tmp_path, monkeypatch):
    s3 = MagicMock()
    s3.get_paginator.return_value.paginate.return_value = [{"Contents": [{"Key": "scans/x/a.pulumi.plan.json"}]}]
    s3.download_file.side_effect = lambda _bucket, _key, dest: __import__("pathlib").Path(dest).write_text("{invalid")
    monkeypatch.setattr(handler, "s3", s3)
    files, errors, _ = handler._download_snapshot("bucket", "scans/x/", str(tmp_path))
    assert files == [] and errors == ["a.pulumi.plan.json"]
    assert not (tmp_path / "a.pulumi.plan.json").exists()


def test_origins_and_ids_distinguish_resources_with_same_rule_and_lines(tmp_path):
    file = tmp_path / "a.pulumi.plan.json"
    file.write_text(json.dumps(plan()))
    findings = [{"file": file.name, "target_type": "terraform", "source": "trivy", "rule_id": "AWS-1",
                 "resource": address, "line_range": [0, 0]} for address in ("aws_s3_bucket.logs", "aws_s3_bucket.other")]
    handler._pulumi_origins(findings, [str(file)], str(tmp_path))
    assert all(f["target_type"] == "pulumi" for f in findings)
    assert findings[0]["origin"]["file"] == "infra/index.ts"
    assert findings[0]["finding_id"] != findings[1]["finding_id"]


def test_invalid_plan_cannot_become_allow_empty_success(monkeypatch):
    monkeypatch.setattr(handler, "_download_snapshot", lambda *args: ([], ["bad.pulumi.plan.json"], {}))
    with pytest.raises(ValueError):
        handler.handler({"pr_id": "test", "s3_prefix": "scans/test", "allow_empty": True}, None)


def test_findings_without_resource_keep_distinct_line_identities(tmp_path):
    file = tmp_path / "a.pulumi.plan.json"
    file.write_text(json.dumps(plan()))
    findings = [{"file": file.name, "source": "checkov", "rule_id": "SECRET", "resource": "",
                 "line_range": [line, line]} for line in (10, 20)]
    handler._pulumi_origins(findings, [str(file)], str(tmp_path))
    assert findings[0]["finding_id"] != findings[1]["finding_id"]


def test_trivy_virtual_files_get_the_correct_plan_provenance(tmp_path, monkeypatch):
    for name in ("first.pulumi.plan.json", "second.pulumi.plan.json"):
        (tmp_path / name).write_text(json.dumps(plan()))
    calls = []
    def scan(target, scanners):
        calls.append((target, scanners))
        return ([{"Target": "main.tf", "ID": "AWS-1"}], [])
    monkeypatch.setattr(handler, "_run_trivy_once", scan)
    records, errors = handler._run_trivy(str(tmp_path))
    assert records[0]["Target"] == "main.tf"
    assert [r["Target"] for r in records[1:]] == ["first.pulumi.plan.json", "second.pulumi.plan.json"]
    assert "terraformplan-json" not in calls[0][1]
    assert all(scanners == "terraformplan-json" for _, scanners in calls[1:])
    assert not errors
