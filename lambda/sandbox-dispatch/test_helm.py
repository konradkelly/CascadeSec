import io
import json
import tarfile

import pytest

import handler
import helm
from test_cdk import FakeS3, tgz


MANIFEST = b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: probe\n"


def request(**overrides):
    return {"kind": "helm-template", "phases": ["execute"], "timeout_seconds": 600,
            "pr_id": "gh-123-7", "app_dir": "charts/app", "project_key": "projects/gh-123-7/a.tgz",
            **overrides}


def test_prepare_needs_no_mirror_or_fetch(monkeypatch):
    s3 = FakeS3()
    monkeypatch.setattr(handler, "s3", s3)
    monkeypatch.setattr(handler, "SANDBOX_BUCKET", "sb")
    monkeypatch.setattr(handler, "ARTIFACTS_BUCKET", "art")
    monkeypatch.setattr(handler, "SANDBOX_ACTIVE", True)
    def forbidden():
        pytest.fail("Helm must not access CodeArtifact")
    monkeypatch.setattr(handler, "_npm_repository_endpoint", forbidden)
    monkeypatch.setattr(handler, "_codeartifact_token", forbidden)
    result = handler.prepare(request(values_files=["env/prod.yaml"], release="probe", namespace="test"))
    prepared = result["prepared"]
    assert not prepared["run_fetch"] and prepared["run_execute"]
    manifest = json.loads(s3.objects[("sb", f"runs/{prepared['run_id']}/execute/manifest.json")])
    assert manifest["HELM_VALUES"] == ["env/prod.yaml"]
    assert manifest["HELM_RELEASE"] == "probe" and manifest["HELM_NAMESPACE"] == "test"
    assert not any(k.startswith("CODEARTIFACT") or k == "DEPS_URL" for k in manifest)


@pytest.mark.parametrize("overrides", [
    {"phases": ["fetch", "execute"]}, {"app_dir": "../app"},
    {"project_key": "projects/another/a.tgz"}, {"values_files": ["../secret"]},
    {"values_files": ["https://example.com/values.yaml"]}, {"values_files": ["a,b.yaml"]},
    {"values_files": "values.yaml"}, {"release": "--post-renderer"},
    {"namespace": "bad/name"}, {"kube_version": "--enable-dns"},
    {"api_versions": ["v1,--enable-dns"]}, {"api_versions": [1]},
])
def test_rejects_invalid_requests(overrides):
    with pytest.raises(handler.BadRequest):
        handler._validate_request(request(**overrides))


@pytest.mark.parametrize("members", [
    {"../manifests.yaml": MANIFEST}, {"manifests.yaml": "symlink"},
    {"manifests.yaml": b"\xff"}, {"manifests.yaml": b"# empty\n---\n"},
    {"manifests.yaml": b"apiVersion: v1\x00"}, {},
    {"manifests.yaml": MANIFEST, "other.yaml": MANIFEST},
])
def test_rejects_hostile_or_empty_output(members):
    with pytest.raises(helm.Hostile):
        helm.read_manifest(io.BytesIO(tgz(members)))


def test_rejects_duplicate_members():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for _ in range(2):
            member = tarfile.TarInfo("manifests.yaml")
            member.size = len(MANIFEST)
            tar.addfile(member, io.BytesIO(MANIFEST))
    with pytest.raises(helm.Hostile):
        helm.read_manifest(io.BytesIO(buf.getvalue()))


def test_rejects_oversized_member(monkeypatch):
    monkeypatch.setattr(helm, "MAX_FILE_BYTES", 5)
    with pytest.raises(helm.Hostile):
        helm.read_manifest(io.BytesIO(tgz({"manifests.yaml": MANIFEST})))


def test_collect_stores_manifest_for_kubernetes_scanning(monkeypatch):
    s3 = FakeS3()
    monkeypatch.setattr(handler, "s3", s3)
    monkeypatch.setattr(handler, "SANDBOX_BUCKET", "sb")
    monkeypatch.setattr(handler, "ARTIFACTS_BUCKET", "art")
    run = "a" * 32
    s3.objects[("sb", f"runs/{run}/execute/output.tgz")] = tgz({"manifests.yaml": MANIFEST})
    phases = {"execute": {"status": "ok", "result": {"status": "ok"}}}
    result = handler._collect_helm(request(), run, phases)
    assert result["status"] == "ok"
    assert result["manifest_key"] == "scans/gh-123-7/charts/app/helm.out/manifests.yaml"
    assert s3.objects[("art", result["manifest_key"])] == MANIFEST
    s3.objects.clear()
    assert handler._collect_helm(request(), run, phases)["status"] == "error"


def test_failures_are_not_empty_success():
    phases = {"execute": {"status": "ok", "result": {"status": "failed", "reason": "missing dependencies"}}}
    assert handler._collect_helm(request(), "a" * 32, phases)["reason"] == "missing dependencies"
    assert handler._collect_helm(request(unavailable=True), "a" * 32, {})["status"] == "unavailable"


def test_helm_result_shaping():
    shaped = handler._shape({"phase": "execute", "kind": "helm-template", "status": "failed",
                             "log_tail": "x" * 5000}, "execute", "helm-template")
    assert shaped["result"]["status"] == "failed"
    assert len(shaped["result"]["log_tail"]) == handler.MAX_LOG_TAIL
