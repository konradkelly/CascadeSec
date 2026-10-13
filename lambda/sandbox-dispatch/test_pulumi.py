import io
import json
import tarfile

import pytest

import handler
import pulumi
from test_cdk import FakeS3, FakeCodeArtifact


def archive(data, name="resources.json", link=False):
    body = json.dumps(data).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        member = tarfile.TarInfo(name)
        if link:
            member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(member)
        else:
            member.size = len(body)
            tar.addfile(member, io.BytesIO(body))
    return io.BytesIO(buf.getvalue())


def document():
    return {"schema_version": 1, "mode": "mock", "project": "test", "stack": "sandbox",
            "resources": [{"type": "aws:s3/bucket:Bucket", "name": "logs", "custom": True,
                           "inputs": {"tags": {"Environment": "test"}},
                           "source": {"file": "index.ts", "line": 5}}]}


def request(**overrides):
    return {"kind": "pulumi-mock", "phases": ["fetch", "execute"], "timeout_seconds": 600,
            "pr_id": "gh-123-7", "app_dir": "infra", "project_key": "projects/gh-123-7/a.tgz",
            **overrides}


def test_prepares_credentials_only_for_fetch(monkeypatch):
    s3 = FakeS3()
    monkeypatch.setattr(handler, "s3", s3)
    monkeypatch.setattr(handler, "codeartifact", FakeCodeArtifact())
    monkeypatch.setattr(handler, "_npm_endpoint", None)
    monkeypatch.setattr(handler, "SANDBOX_BUCKET", "sb")
    monkeypatch.setattr(handler, "ARTIFACTS_BUCKET", "art")
    monkeypatch.setattr(handler, "SANDBOX_ACTIVE", True)
    result = handler.prepare(request(config={"test:environment": "dev"}))
    run = result["prepared"]["run_id"]
    execute = json.loads(s3.objects[("sb", f"runs/{run}/execute/manifest.json")])
    assert execute["PULUMI_CONFIG"] == {"test:environment": "dev"}
    assert "CODEARTIFACT_TOKEN" not in execute
    assert execute["DEPS_URL"].split("?")[0].endswith(f"runs/{run}/fetch/output.tgz")


@pytest.mark.parametrize("overrides", [
    {"phases": ["execute"]}, {"app_dir": "../infra"}, {"config": {"x": 1}},
    {"mock_calls": {"aws:getVpc": {"id": "fake"}}},
    {"project_key": "projects/another-pr/a.tgz"},
])
def test_invalid_requests(overrides):
    with pytest.raises(handler.BadRequest):
        handler._validate_request(request(**overrides))


def test_resources_validated_and_source_prefixed():
    data = pulumi.read_resources(archive(document()), "infra")
    assert data["resources"][0]["source"] == {"file": "infra/index.ts", "line": 5}


@pytest.mark.parametrize("name,link", [("../resources.json", False), ("resources.json", True)])
def test_hostile_archive(name, link):
    with pytest.raises(pulumi.Hostile):
        pulumi.read_resources(archive(document(), name, link), ".")


@pytest.mark.parametrize("source", [{"file": "../outside.ts", "line": 1},
                                    {"file": "index.ts", "line": True}])
def test_hostile_source(source):
    data = document()
    data["resources"][0]["source"] = source
    with pytest.raises(pulumi.Hostile):
        pulumi.read_resources(archive(data), ".")


def test_collect_stores_validated_output_and_reports_count(monkeypatch):
    s3 = FakeS3()
    monkeypatch.setattr(handler, "s3", s3)
    monkeypatch.setattr(handler, "SANDBOX_BUCKET", "sb")
    run = "a" * 32
    monkeypatch.setattr(handler, "ARTIFACTS_BUCKET", "art")
    data = document()
    data.update(schema_version=2, provider_versions={"aws": "7.48.0"})
    data["resources"][0].update(urn="urn:pulumi:sandbox::test::aws:s3/bucket:Bucket::logs", references={}, dependencies={})
    s3.objects[("sb", f"runs/{run}/execute/output.tgz")] = archive(data).getvalue()
    phases = {p: {"status": "ok", "result": {"status": "ok"}} for p in ("fetch", "execute")}
    result = handler._collect_pulumi(request(), run, phases)
    assert result["status"] == "ok" and result["resources"] == 1
    stored = json.loads(s3.objects[("sb", result["resources_key"])])
    assert stored["resources"][0]["source"]["file"] == "infra/index.ts"
    assert ("art", result["plan_key"]) in s3.objects


def test_failure_does_not_report_empty_success():
    phases = {"fetch": {"status": "ok", "result": {"status": "failed", "reason": "npm failed"}}}
    result = handler._collect_pulumi(request(), "a" * 32, phases)
    assert result["status"] == "failed" and result["reason"] == "npm failed"


def test_rejects_overflowing_json_numbers():
    data = document()
    data["resources"][0]["inputs"] = {"value": float("inf")}
    raw = archive(data).getvalue()
    # Repack with valid JSON syntax that overflows Python's float parser.
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        payload = tar.extractfile("resources.json").read().replace(b"Infinity", b"1e309")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        member = tarfile.TarInfo("resources.json")
        member.size = len(payload)
        tar.addfile(member, io.BytesIO(payload))
    with pytest.raises(pulumi.Hostile):
        pulumi.read_resources(io.BytesIO(buf.getvalue()), ".")
