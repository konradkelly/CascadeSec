import io
import json
from types import SimpleNamespace

import pytest

import sandbox


def args(root, **overrides):
    return SimpleNamespace(dir=str(root), app_dir="charts/app", values=["prod.yaml"],
                           release="probe", namespace="test", kube_version="1.30.0",
                           api_versions=["apps/v1"], output=str(root / "rendered.yaml"),
                           log=False, scan=True, **overrides)


@pytest.mark.parametrize("scan_errors", [[], [{"file": "manifests.yaml", "reason": "bad YAML"}]])
def test_render_and_scan_contract(tmp_path, monkeypatch, scan_errors):
    chart = tmp_path / "charts" / "app"
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: probe\nversion: 0.1.0\n")
    (tmp_path / "prod.yaml").write_text("privileged: false\n")
    monkeypatch.setattr(sandbox, "outputs", lambda: {
        "active": True, "state_machine_arn": "arn:aws:states:us-west-2:123:stateMachine:sb",
        "artifacts_bucket": "art"})
    monkeypatch.setattr(sandbox, "tf_output", lambda _: "scanner")
    uploads, executions, scans = [], [], []
    manifest = b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: probe\n"
    class Client:
        def put_object(self, **kwargs):
            uploads.append(kwargs)
        def get_object(self, **kwargs):
            return {"Body": io.BytesIO(manifest)}
        def invoke(self, **kwargs):
            scans.append(json.loads(kwargs["Payload"]))
            return {"Payload": io.BytesIO(json.dumps({"finding_count": 0, "scan_errors": scan_errors}).encode())}
    monkeypatch.setattr(sandbox.boto3, "client", lambda *a, **kw: Client())
    def wait(sfn, arn, payload):
        executions.append(payload)
        return {"status": "SUCCEEDED", "output": json.dumps({"phases": {}, "helm": {
            "status": "ok", "manifest_key": "scans/manual/helm.out/manifests.yaml", "scan_prefix": "scans/manual/"}})}
    monkeypatch.setattr(sandbox, "start_and_wait", wait)
    if scan_errors:
        with pytest.raises(SystemExit) as exit:
            sandbox.cmd_helm(args(tmp_path))
        assert exit.value.code == 1
    else:
        sandbox.cmd_helm(args(tmp_path))
    assert executions[0]["kind"] == "helm-template"
    assert executions[0]["phases"] == ["execute"]
    assert executions[0]["values_files"] == ["prod.yaml"]
    assert len(uploads) == 1
    assert scans == [{"pr_id": executions[0]["pr_id"], "s3_prefix": "scans/manual/", "persist": False}]
    assert (tmp_path / "rendered.yaml").read_bytes() == manifest
    assert (tmp_path / "rendered.findings.json").is_file()


def test_invalid_chart_path_fails_before_aws(tmp_path):
    options = args(tmp_path)
    options.app_dir = "../outside"
    with pytest.raises(SystemExit, match="repository-relative"):
        sandbox.cmd_helm(options)
