"""The split that lets the scanner run outside Lambda (docs/cli-spec.md
§3.1): scan_directory touches no AWS service, _admit is the one rule for
what a snapshot file is, and importing the module needs no AWS
configuration.

In its own file so test_handler.py stays byte-for-byte as it was: the
refactor's bar is that the existing tests pass unchanged.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import handler

ARM = json.dumps({"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                  "resources": []})
CFN = json.dumps({"AWSTemplateFormatVersion": "2010-09-09",
                  "Resources": {"B": {"Type": "AWS::S3::Bucket"}}})
PULUMI = json.dumps({"planned_values": {"root_module": {"resources": []}},
                     "configuration": {"root_module": {"resources": []}},
                     "cascade_pulumi": {"mode": "mock", "sources": {}}})


# ---------- _admit ----------

@pytest.mark.parametrize("name,content,expected,stays", [
    ("main.tf", 'resource "x" "y" {}', ("keep", None), True),
    ("app.yaml", "kind: Pod", ("keep", None), True),
    ("vars.tf.json", "{}", ("keep", None), True),               # Terraform's, by suffix
    ("storage.json", ARM, ("keep", "arm"), True),
    ("stack.template", CFN, ("keep", "cloudformation"), True),
    ("a.pulumi.plan.json", PULUMI, ("keep", "pulumi"), True),
    ("package-lock.json", '{"lockfileVersion": 3}', ("drop", None), False),
    ("broken.json", ARM[:-5], ("unreadable", None), False),     # claims ARM, will not parse
    ("bad.pulumi.plan.json", "{invalid", ("unreadable", None), False),
])
def test_admit_decides_and_removes_what_it_does_not_keep(tmp_path, name, content, expected, stays):
    path = tmp_path / name
    path.write_text(content)

    assert handler._admit(name, str(path)) == expected
    # Removed from disk, not just left off a list: checkov's secrets runner
    # reads the directory.
    assert path.exists() is stays


@pytest.mark.parametrize("path,candidate", [
    ("infra/main.tf", True), ("k8s/app.yml", True), ("a.bicep", True), ("x.json", True),
    ("stack.template", True), ("README.md", False), ("main.py", False), ("cdk.out/x.template.sources", False),
])
def test_what_is_worth_reading_at_all(path, candidate):
    assert handler._is_candidate(path) is candidate


def test_a_snapshot_accumulates_what_admit_decided(tmp_path):
    files = {"main.tf": "", "arm.json": ARM, "lock.json": "{}", "broken.json": ARM[:-5]}
    snapshot = handler.Snapshot()
    for name, content in files.items():
        (tmp_path / name).write_text(content)
        snapshot.add(name, str(tmp_path / name))

    assert [Path(p).name for p in snapshot.downloaded] == ["main.tf", "arm.json"]
    assert snapshot.classifications == {"arm.json": "arm"}
    assert snapshot.unreadable_templates == ["broken.json"]


# ---------- scan_directory ----------

class NoAws:
    """Any use of a client is a failure: scan_directory must not reach AWS."""

    def __getattr__(self, name):
        raise AssertionError(f"scan_directory used an AWS client ({name})")


def test_scan_directory_touches_no_aws_service(tmp_path):
    # _run_trivy's shape: one flat record per misconfiguration.
    trivy = [{"Target": "main.tf", "Class": "config", "ID": "AWS-0086", "Title": "t", "Description": "d",
              "Severity": "HIGH", "CauseMetadata": {"Resource": "aws_s3_bucket.b", "StartLine": 1, "EndLine": 3}}]
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
    with patch.object(handler, "s3", NoAws()), patch.object(handler, "dynamodb", NoAws()), \
            patch.object(handler, "_run_trivy", return_value=(trivy, ["bad.tf"])), \
            patch.object(handler, "_run_checkov", return_value={}), \
            patch.object(handler, "_run_kics", return_value={}):
        findings, scan_errors = handler.scan_directory(
            str(tmp_path), "pr-1", [str(tmp_path / "main.tf")], ["broken.json"], {})

    assert [(f["source"], f["rule_id"], f["file"]) for f in findings] == [("trivy", "AWS-0086", "main.tf")]
    assert scan_errors == ["bad.tf", "broken.json"]


def test_the_lambda_passes_its_source_maps_in(tmp_path):
    """The one thing the scan needs from S3 beyond the snapshot is fetched
    by the handler and handed over, so the origin logic stays in one place."""
    maps = {"cdk.out/App.template.json": {"resources": {}}}
    seen = {}

    def scan(work_dir, pr_id, downloaded, unreadable, classifications, cdk_source_maps=None):
        seen["maps"] = cdk_source_maps
        return [], []

    with patch.object(handler, "_download_snapshot", return_value=(["x"], [], {})), \
            patch.object(handler, "_cdk_source_maps", return_value=maps), \
            patch.object(handler, "scan_directory", side_effect=scan):
        handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/", "persist": False}, None)

    assert seen["maps"] is maps


# ---------- importing with no AWS configuration ----------

def test_the_module_imports_with_no_aws_configuration():
    """Local mode imports this on a laptop with no AWS profile. A client made
    at import time raised NoRegionError before any file was scanned."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env["AWS_CONFIG_FILE"] = env["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
    result = subprocess.run([sys.executable, "-c", "import handler"], cwd=Path(handler.__file__).parent,
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
