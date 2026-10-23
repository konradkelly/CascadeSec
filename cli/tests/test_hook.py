"""`cascadesec hook` and .pre-commit-hooks.yaml (cli-spec §7): which files
it judges, and that the manifest pre-commit reads agrees with what the
scanner admits. Docker is faked at the subprocess boundary; a real
pre-commit run is recorded in cli-spec §7."""

import ast
import io
import json
import re
import subprocess
from pathlib import Path

import pytest

from cascadesec import hook
from cascadesec import main as cli

REPO = Path(__file__).resolve().parents[2]


def finding(fp, file, severity="HIGH"):
    return {"fingerprint": fp, "source": "trivy", "rule_id": "AWS-0086", "file": file,
            "line_range": [1, 1], "severity": severity, "candidates": []}


class FakeDocker:
    def __init__(self, findings=(), errors=(), apps=()):
        self.result = {"scanned_files": 3, "findings": list(findings), "scan_errors": list(errors),
                       "unscanned_apps": list(apps)}
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, json.dumps(self.result), "")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr("cascadesec.scan.shutil.which", lambda name: "/usr/bin/docker")
    return tmp_path


def run(argv, repo, docker):
    out = io.StringIO()
    code = cli.main(argv, stdout=out, env={"CASCADESEC_SCANNER_IMAGE": "img:1"}, cwd=repo, run=docker)
    return code, out.getvalue()


def test_it_scans_the_changed_files_directories_and_judges_only_the_files(repo):
    docker = FakeDocker([finding("a", "infra/s3.tf"), finding("b", "infra/other.tf"), finding("c", "main.tf")])
    code, out = run(["--format", "json", "hook", "infra/s3.tf", "main.tf"], repo, docker)

    result = json.loads(out)
    assert code == 1
    assert sorted(f["fingerprint"] for f in result["findings"]) == ["a", "c"]
    assert result["outside_changes_count"] == 1          # other.tf: in the directory, not changed
    (cmd,) = docker.calls
    assert [cmd[i + 1] for i, x in enumerate(cmd) if x == "--only-dir"] == [".", "infra"]
    assert cmd[cmd.index("--network") + 1] == "none"


def test_a_baselined_finding_in_a_changed_file_does_not_block(repo):
    (repo / ".cascadesec-baseline.json").write_text(json.dumps(
        {"version": 1, "scanner_image": "img:1", "findings": [{"fingerprint": "a"}]}))
    code, out = run(["--format", "json", "hook", "s3.tf"], repo, FakeDocker([finding("a", "s3.tf")]))
    assert code == 0
    assert json.loads(out)["baselined_count"] == 1


def test_a_changed_file_that_does_not_parse_blocks(repo):
    code, _ = run(["hook", "bad.tf"], repo, FakeDocker(errors=["bad.tf", "untouched.tf"]))
    assert code == 3


def test_an_app_blocks_only_when_a_changed_file_is_inside_it(repo):
    apps = [{"path": "infra", "kind": "helm", "reason": "r"}]
    assert run(["hook", "infra/values.yaml"], repo, FakeDocker(apps=apps))[0] == 3
    assert run(["hook", "main.tf"], repo, FakeDocker(apps=apps))[0] == 0


def test_no_files_is_a_pass_without_docker(repo):
    docker = FakeDocker()
    code, out = run(["--format", "table", "hook"], repo, docker)
    assert (code, out, docker.calls) == (0, "", [])


def test_a_file_outside_the_repository_is_refused(repo, tmp_path):
    code, _ = run(["hook", "../elsewhere.tf"], repo, FakeDocker())
    assert code == 2


def test_the_table_says_what_to_do_when_it_blocks(repo):
    _, out = run(["--format", "table", "hook", "s3.tf"], repo, FakeDocker([finding("a", "s3.tf")]))
    assert "checked 1 changed file" in out
    assert "cascadesec baseline" in out and "--no-verify" in out


def test_directories_are_posix_and_include_the_root():
    assert hook.directories({"main.tf", "infra/a.tf", "infra/b.tf", "k8s/x/y.yaml"}) == [".", "infra", "k8s/x"]


# ---------- the manifest pre-commit reads ----------

def manifest():
    return (REPO / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")


def test_the_manifest_runs_serially_on_push_with_the_file_names():
    text = manifest()
    assert re.search(r"^- id: cascadesec$", text, re.M)
    assert re.search(r"^\s*entry: cascadesec hook$", text, re.M)
    assert re.search(r"^\s*pass_filenames: true$", text, re.M)
    assert re.search(r"^\s*require_serial: true$", text, re.M)
    assert re.search(r"^\s*stages: \[pre-push\]$", text, re.M)


def test_the_manifest_matches_what_the_scanner_admits():
    """A suffix the scanner admits and the hook's pattern misses would let a
    change through unscanned; the reverse would run Docker for nothing."""
    pattern = re.compile(re.search(r"^\s*files: (.+)$", manifest(), re.M).group(1))
    source = (REPO / "lambda" / "iac-scanner" / "handler.py").read_text(encoding="utf-8")
    suffixes = ast.literal_eval(re.search(r"^SNAPSHOT_SUFFIXES = (\(.*?\))", source, re.S | re.M).group(1))
    for suffix in (*suffixes, ".json", ".template"):              # admitted, or sniffed
        assert pattern.search("dir/file" + suffix), suffix
    for other in ("main.py", "README.md", "lib/stack.ts", "notes.txt"):
        assert not pattern.search(other), other


def test_the_hook_prints_the_table_even_without_a_terminal(repo):
    """pre-commit captures output, so it is never a TTY; a person reads it."""
    _, out = run(["hook", "s3.tf"], repo, FakeDocker([finding("a", "s3.tf")]))
    assert out.startswith("CascadeSec checked")
    _, out = run(["--format", "json", "hook", "s3.tf"], repo, FakeDocker([finding("a", "s3.tf")]))
    assert json.loads(out)["exit_code"] == 1
