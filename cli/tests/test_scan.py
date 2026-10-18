"""`cascadesec scan` in local mode: the docker line it runs, the exit code
it decides (cli-spec §5), and what it prints. Docker is faked at the
subprocess boundary; the image itself is exercised by iac-scanner's
test_local_main.py and the live runs recorded in cli-spec §3.4."""

import io
import json
import subprocess

import pytest

from cascadesec import main as cli
from cascadesec import scan

HIGH = {"source": "trivy", "rule_id": "AWS-0086", "file": "s3.tf", "line_range": [3, 9], "severity": "HIGH",
        "target_type": "terraform",
        "candidates": [{"framework": "CIS-AWS-1.4", "control_id": "2.1.5", "title": "Block public access"},
                       {"framework": "OWASP-CloudNative", "control_id": "CNAS-6", "title": "t"}]}
UNRATED = {"source": "checkov", "rule_id": "CKV_AZURE_43", "file": "a.json", "line_range": [1, 1],
           "severity": "UNKNOWN", "target_type": "arm", "candidates": [], "raw_reason": "hygiene"}
LOW = {**HIGH, "severity": "LOW", "rule_id": "AWS-0089"}
CDK = {**HIGH, "target_type": "cdk", "detection_only": True, "file": "cdk.out/T.json",
       "origin": {"file": "lib/net.ts", "line": 8}}
APP = {"path": "infra", "kind": "cdk", "reason": "a CDK app: not run locally"}


def image_result(findings=(), scan_errors=(), apps=()):
    return {"scanned_files": 3, "findings": list(findings), "scan_errors": list(scan_errors),
            "unscanned_apps": list(apps)}


class FakeDocker:
    def __init__(self, result=None, returncode=0, stdout=None, stderr=""):
        self.stdout = stdout if stdout is not None else json.dumps(result or image_result())
        self.returncode, self.stderr = returncode, stderr
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


def run(argv, tmp_path, docker, env=None, monkeypatch=None):
    if monkeypatch:
        monkeypatch.setattr(scan.shutil, "which", lambda name: "/usr/bin/docker")
    out = io.StringIO()
    code = cli.main(argv, stdout=out, env=env or {}, cwd=tmp_path, run=docker)
    return code, out.getvalue()


# ---------- the docker line ----------

def test_the_image_runs_offline_read_only_on_an_absolute_mount(tmp_path, monkeypatch):
    docker = FakeDocker()
    run(["--format", "json", "scan", str(tmp_path)], tmp_path, docker, monkeypatch=monkeypatch)

    (cmd,) = docker.calls
    assert cmd[:2] == ["docker", "run"]
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd and cmd[cmd.index("--tmpfs") + 1] == "/tmp"
    mount = cmd[cmd.index("-v") + 1]
    assert mount.endswith(":/src:ro") and mount.startswith(str(tmp_path.resolve())[:3])
    assert cmd[-2:] == ["/var/task/local_main.py", "/src"]
    assert scan.SCANNER_IMAGE in cmd


def test_the_image_can_be_overridden(tmp_path, monkeypatch):
    docker = FakeDocker()
    run(["--format", "json", "scan", str(tmp_path)], tmp_path, docker,
        env={"CASCADESEC_SCANNER_IMAGE": "cascadesec-scanner:local"}, monkeypatch=monkeypatch)
    assert "cascadesec-scanner:local" in docker.calls[0]

    run(["--format", "json", "scan", str(tmp_path), "--image", "x:1"], tmp_path, docker,
        env={"CASCADESEC_SCANNER_IMAGE": "cascadesec-scanner:local"}, monkeypatch=monkeypatch)
    assert "x:1" in docker.calls[1]


def test_no_docker_says_so_and_never_falls_back(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    code, out = run(["scan", str(tmp_path)], tmp_path, FakeDocker())
    assert (code, out) == (2, "")
    assert "Docker" in capsys.readouterr().err


@pytest.mark.parametrize("docker,code,words", [
    (FakeDocker(returncode=1, stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock"),
     2, "not running"),
    (FakeDocker(returncode=125, stderr="Unable to find image 'x:1' locally\npull access denied"), 4, "exited 125"),
    (FakeDocker(stdout="not json"), 4, "other than its JSON"),
])
def test_docker_failures_name_the_problem(tmp_path, monkeypatch, capsys, docker, code, words):
    got, _ = run(["scan", str(tmp_path)], tmp_path, docker, monkeypatch=monkeypatch)
    assert got == code
    assert words in capsys.readouterr().err


def test_a_missing_directory_is_a_usage_error_before_docker(tmp_path, monkeypatch):
    docker = FakeDocker()
    code, _ = run(["scan", str(tmp_path / "nope")], tmp_path, docker, monkeypatch=monkeypatch)
    assert (code, docker.calls) == (2, [])


# ---------- exit codes (§5) ----------

@pytest.mark.parametrize("result,argv,code", [
    (image_result([HIGH]), [], 1),
    (image_result([LOW, UNRATED]), [], 0),                      # nothing at or above high
    (image_result([UNRATED]), ["--fail-on", "any"], 1),         # any counts the unrated
    (image_result([HIGH]), ["--fail-on", "none"], 0),
    (image_result([LOW]), ["--fail-on", "low"], 1),
    (image_result([], scan_errors=["bad.tf"]), [], 3),
    (image_result([], apps=[APP]), [], 3),                       # an app not run is not clean
    (image_result([HIGH], scan_errors=["bad.tf"]), [], 3),      # 3 takes precedence over 1
    (image_result([HIGH], scan_errors=["bad.tf"]), ["--allow-scan-errors"], 1),
    (image_result([LOW], apps=[APP]), ["--allow-scan-errors"], 0),
])
def test_the_exit_code(tmp_path, monkeypatch, result, argv, code):
    got, out = run(["--format", "json", "scan", str(tmp_path), *argv], tmp_path, FakeDocker(result),
                   monkeypatch=monkeypatch)
    assert got == code
    assert json.loads(out)["exit_code"] == code


# ---------- what it prints ----------

def test_json_is_the_images_result_plus_the_decision(tmp_path, monkeypatch):
    _, out = run(["--format", "json", "scan", str(tmp_path)], tmp_path,
                 FakeDocker(image_result([HIGH, UNRATED])), monkeypatch=monkeypatch)
    result = json.loads(out)
    assert (result["fail_on"], result["failing_count"], result["exit_code"]) == ("high", 1, 1)
    assert result["findings"][0]["candidates"][0]["control_id"] == "2.1.5"
    assert not any(k.startswith("_") for k in result)


def test_the_table_shows_candidates_raw_reasons_and_what_was_not_scanned(tmp_path, monkeypatch):
    code, out = run(["--format", "table", "scan", str(tmp_path)], tmp_path,
                    FakeDocker(image_result([UNRATED, HIGH, CDK], scan_errors=["bad.tf"], apps=[APP])),
                    monkeypatch=monkeypatch)
    assert code == 3
    assert "CIS-AWS-1.4 2.1.5, +1" in out
    assert "raw (hygiene)" in out
    assert "lib/net.ts:8" in out and "(detection only)" in out
    assert out.index("HIGH") < out.index("UNKNOWN")               # worst first
    assert "bad.tf" in out and "infra: a CDK app" in out
    assert "Exit 3: incomplete" in out
    assert "not its choice" in out                                # candidates are not the citation


def test_output_writes_the_result_and_the_table_still_prints(tmp_path, monkeypatch):
    target = tmp_path / "result.json"
    _, out = run(["--format", "table", "scan", str(tmp_path), "--output", str(target)], tmp_path,
                 FakeDocker(image_result([HIGH])), monkeypatch=monkeypatch)
    assert "AWS-0086" in out
    assert "Exit 1" in target.read_text(encoding="utf-8")         # --format table went to the file too

    _, _ = run(["--format", "json", "scan", str(tmp_path), "--output", str(target)], tmp_path,
               FakeDocker(image_result([HIGH])), monkeypatch=monkeypatch)
    assert json.loads(target.read_text(encoding="utf-8"))["failing_count"] == 1


def test_version_names_the_scanner_image(tmp_path):
    code, out = run(["--format", "json", "version"], tmp_path, FakeDocker(),
                    env={"CASCADESEC_SCANNER_IMAGE": "cascadesec-scanner:local"})
    assert json.loads(out)["scanner_image"] == "cascadesec-scanner:local"
