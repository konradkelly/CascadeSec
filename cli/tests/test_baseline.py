"""The baseline, --changed-only and skip_apps (cli-spec §3.5, §6): what each
holds back from the verdict, and that every finding held back is counted.
Docker and git are faked at the subprocess boundary."""

import io
import json
import subprocess
from pathlib import Path

import pytest

from cascadesec import baseline, config
from cascadesec import main as cli
from cascadesec.errors import CliError


def finding(fp, file="s3.tf", rule_id="AWS-0086", severity="HIGH", origin=None, line=3):
    f = {"fingerprint": fp, "source": "trivy", "rule_id": rule_id, "file": file,
         "line_range": [line, line], "severity": severity, "title": "t", "candidates": []}
    if origin:
        f["origin"] = origin
    return f


class Fake:
    """Docker answers with a canned scan; git with canned file lists."""

    def __init__(self, findings=(), errors=(), apps=(), changed=(), untracked=(), git_ok=True):
        self.result = {"scanned_files": 2, "findings": list(findings), "scan_errors": list(errors),
                       "unscanned_apps": list(apps)}
        self.changed, self.untracked, self.git_ok = list(changed), list(untracked), git_ok
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        if cmd[0] == "git":
            if not self.git_ok:
                return subprocess.CompletedProcess(cmd, 128, "", "fatal: bad revision 'nope'")
            lines = self.changed if "diff" in cmd else self.untracked
            return subprocess.CompletedProcess(cmd, 0, "\n".join(lines) + "\n", "")
        return subprocess.CompletedProcess(cmd, 0, json.dumps(self.result), "")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr("cascadesec.scan.shutil.which", lambda name: "/usr/bin/docker")
    return tmp_path


def run(argv, repo, fake, env=None):
    out = io.StringIO()
    code = cli.main(argv, stdout=out, env=env or {"CASCADESEC_SCANNER_IMAGE": "img:1"}, cwd=repo, run=fake)
    return code, out.getvalue()


def scan_json(repo, fake, *flags):
    code, out = run(["--format", "json", "scan", str(repo), *flags], repo, fake)
    return code, json.loads(out)


# ---------- the file ----------

def test_one_entry_per_fingerprint_in_an_order_that_diffs_well():
    entries = baseline.entries_for([finding("b", file="z.tf"), finding("a", file="a.tf"), finding("a", file="a.tf", line=9)])
    assert [e["fingerprint"] for e in entries] == ["a", "b"]
    assert set(entries[0]) == {"fingerprint", "source", "rule_id", "file", "line", "severity", "title"}


@pytest.mark.parametrize("content", ["not json", '{"version": 2, "findings": []}', '{"version": 1}',
                                     '{"version": 1, "findings": [{"rule_id": "x"}]}'])
def test_a_file_that_is_not_a_baseline_is_refused(tmp_path, content):
    (tmp_path / "b.json").write_text(content)
    with pytest.raises(CliError) as e:
        baseline.load(tmp_path / "b.json")
    assert e.value.code == 2


def test_prune_removes_what_no_longer_fires_and_adds_nothing():
    document = {"findings": [{"fingerprint": "kept"}, {"fingerprint": "gone"}]}
    assert baseline.prune(document, [finding("kept"), finding("brand-new")]) == [{"fingerprint": "kept"}]


# ---------- scan with a baseline ----------

def test_baselined_findings_leave_the_verdict_and_are_counted(repo):
    run(["baseline", str(repo)], repo, Fake([finding("old")]))
    code, result = scan_json(repo, Fake([finding("old"), finding("new", severity="LOW")]))

    assert code == 0                                   # the HIGH one is baselined; the new one is LOW
    assert [f["fingerprint"] for f in result["findings"]] == ["new"]
    assert result["baselined_count"] == 1
    assert result["baseline"].endswith(baseline.FILE)


def test_a_baselined_finding_that_stops_firing_is_listed_as_fixed(repo):
    run(["baseline", str(repo)], repo, Fake([finding("a"), finding("b", file="es.tf")]))
    _, result = scan_json(repo, Fake([finding("a")]))
    assert [e["file"] for e in result["baseline_fixed"]] == ["es.tf"]

    code, out = run(["--format", "table", "scan", str(repo)], repo, Fake([finding("a")]))
    assert "no longer fire; `cascadesec baseline --prune`" in out


def test_no_baseline_and_a_named_missing_baseline(repo):
    run(["baseline", str(repo)], repo, Fake([finding("old")]))
    code, result = scan_json(repo, Fake([finding("old")]), "--no-baseline")
    assert (code, result["baselined_count"], result["baseline"]) == (1, 0, None)

    code, _ = run(["scan", str(repo), "--baseline", str(repo / "nope.json")], repo, Fake())
    assert code == 2


def test_a_baseline_from_another_scanner_image_is_warned_about(repo, capsys):
    run(["baseline", str(repo)], repo, Fake([finding("old")]), env={"CASCADESEC_SCANNER_IMAGE": "img:1"})
    capsys.readouterr()
    run(["scan", str(repo)], repo, Fake([finding("old")]), env={"CASCADESEC_SCANNER_IMAGE": "img:2"})
    assert "written with img:1" in capsys.readouterr().err


def test_writing_a_baseline_reports_what_changed(repo):
    _, out = run(["--format", "json", "baseline", str(repo)], repo, Fake([finding("a"), finding("b")]))
    assert json.loads(out)["added"] == 2
    _, out = run(["--format", "json", "baseline", str(repo)], repo, Fake([finding("a"), finding("c")]))
    assert (json.loads(out)["added"], json.loads(out)["removed"]) == (1, 1)
    document = json.loads((repo / baseline.FILE).read_text())
    assert document["scanner_image"] == "img:1" and document["version"] == 1


def test_prune_needs_a_baseline_and_warns_on_an_incomplete_scan(repo, capsys):
    code, _ = run(["baseline", str(repo), "--prune"], repo, Fake())
    assert code == 2
    code, _ = run(["baseline", str(repo)], repo, Fake([finding("a")], errors=["bad.tf"]))
    assert code == 0
    assert "incomplete" in capsys.readouterr().err


# ---------- --changed-only ----------

def test_changed_only_reports_findings_errors_and_apps_in_changed_files(repo):
    fake = Fake([finding("a", file="ec2.tf"), finding("b", file="s3.tf"),
                 finding("c", file="cdk.out/T.json", origin={"file": "lib/net.ts", "line": 3})],
                errors=["ec2.tf", "old.tf"],
                apps=[{"path": "infra", "kind": "cdk", "reason": "r"}, {"path": "chart", "kind": "helm", "reason": "r"}],
                changed=["ec2.tf", "lib/net.ts"], untracked=["infra/new.ts"])
    _, result = scan_json(repo, fake, "--changed-only", "main")

    assert sorted(f["fingerprint"] for f in result["findings"]) == ["a", "c"]   # c by its source line
    assert result["scan_errors"] == ["ec2.tf"]
    assert [a["path"] for a in result["unscanned_apps"]] == ["infra"]           # a new file inside it
    assert result["outside_changes_count"] == 1
    diff_call = next(c for c in fake.calls if "diff" in c)
    assert diff_call[-3:] == ["--relative", "main", "--"]


def test_a_baselined_finding_outside_the_changes_is_not_reported_as_fixed(repo):
    """Left out by --changed-only is not the same as fixed."""
    run(["baseline", str(repo)], repo, Fake([finding("a", file="s3.tf")]))
    _, result = scan_json(repo, Fake([finding("a", file="s3.tf")], changed=["ec2.tf"]), "--changed-only", "HEAD")
    assert result["baseline_fixed"] == []


def test_a_bad_revision_is_a_usage_error(repo, capsys):
    code, _ = run(["scan", str(repo), "--changed-only", "nope"], repo, Fake(git_ok=False))
    assert code == 2
    assert "bad revision" in capsys.readouterr().err


# ---------- skip_apps ----------

def test_a_skipped_app_is_reported_as_skipped_not_unscanned(repo):
    (repo / ".cascadesec.toml").write_text('[[skip_apps]]\npath = "infra"\nreason = "never deployed"\n')
    code, result = scan_json(repo, Fake(apps=[{"path": "infra", "kind": "cdk", "reason": "r"}]))

    assert code == 0                                   # the only unscanned app was skipped
    assert result["unscanned_apps"] == []
    assert result["skipped_apps"][0]["reason"] == "never deployed"


def test_a_skip_is_resolved_from_its_own_file_not_the_scan_root(repo):
    sub = repo / "platform"
    sub.mkdir()
    (repo / ".cascadesec.toml").write_text('[[skip_apps]]\npath = "platform/infra"\nreason = "lab only"\n')
    _, result = scan_json(sub, Fake(apps=[{"path": "infra", "kind": "cdk", "reason": "r"}]))
    assert [a["path"] for a in result["skipped_apps"]] == ["infra"]


@pytest.mark.parametrize("toml,words", [
    ('[[skip_apps]]\npath = "infra"\n', "needs a reason"),
    ('[[skip_apps]]\nreason = "x"\n', "needs a path"),
    ('skip_apps = "infra"\n', "array of tables"),
])
def test_a_skip_without_its_reason_is_refused_before_scanning(repo, toml, words, capsys):
    (repo / ".cascadesec.toml").write_text(toml)
    fake = Fake()
    code, _ = run(["scan", str(repo)], repo, fake)
    assert code == 2
    assert fake.calls == []                            # refused before Docker was touched
    assert words in capsys.readouterr().err


def test_skip_apps_is_refused_in_a_users_own_settings(tmp_path):
    user = tmp_path / "appdata" / "cascadesec"
    user.mkdir(parents=True)
    (user / "config.toml").write_text('[[skip_apps]]\npath = "x"\nreason = "y"\n')
    with pytest.raises(CliError) as e:
        config.load(cwd=tmp_path, env={"APPDATA": str(tmp_path / "appdata"),
                                       "XDG_CONFIG_HOME": str(tmp_path / "appdata")})
    assert "repository" in str(e.value)
