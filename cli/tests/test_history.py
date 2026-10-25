"""Judging a change against the version before it (history.py; cli-spec
§6, §7): a finding blocks when the change brought it, in whichever file it
lands, and an old one blocks nobody. git is real, in a temporary
repository; Docker is faked (conftest.Scanner)."""

import ast
import io
import json
import re
import subprocess
import sys
import types
from pathlib import Path

from cascadesec import history
from cascadesec import main as cli
from conftest import Scanner

REPO = Path(__file__).resolve().parents[2]
ENV = {"CASCADESEC_SCANNER_IMAGE": "img:1"}


def finding(fp, file, severity="HIGH"):
    return {"fingerprint": fp, "source": "trivy", "rule_id": "AWS-0086", "file": file,
            "line_range": [1, 1], "severity": severity, "candidates": []}


def push(from_ref, to_ref):
    return {"PRE_COMMIT_FROM_REF": from_ref, "PRE_COMMIT_TO_REF": to_ref}


def hook(repo, scanner, *files, env=None, fmt="json"):
    out = io.StringIO()
    code = cli.main(["--format", fmt, "hook", *files], stdout=out, env={**ENV, **(env or {})},
                    cwd=repo.path, run=scanner)
    return code, (json.loads(out.getvalue()) if fmt == "json" else out.getvalue())


def scan(repo, scanner, *flags):
    out = io.StringIO()
    code = cli.main(["--format", "json", "scan", str(repo.path), *flags], stdout=out, env=ENV,
                    cwd=repo.path, run=scanner)
    return code, json.loads(out.getvalue())


def fingerprints(result):
    return [f["fingerprint"] for f in result["findings"]]


# ---------- the hook ----------

def test_a_push_blocks_on_a_finding_it_brought_into_a_file_it_did_not_touch(git_repo):
    """The case that let a public bucket through: the push changes only
    variables.tf, and the findings it brings land in main.tf."""
    base = git_repo.commit({"main.tf": "bucket\n", "variables.tf": "default = true\n"})
    pushed = git_repo.commit({"variables.tf": "default = false\n"})
    scanner = Scanner(now=[finding("old", "main.tf"), finding("opened", "main.tf")],
                      earlier=[finding("old", "main.tf")])
    code, result = hook(git_repo, scanner, "variables.tf", env=push(base, pushed))

    assert code == 1
    assert fingerprints(result) == ["opened"]
    assert (result["compared_with"], result["preexisting_count"]) == (base, 1)
    assert scanner.exported == [["main.tf", "variables.tf"]]


def test_an_edit_to_a_file_with_old_findings_goes_through(git_repo):
    """A typo fixed in a file that already had a public bucket: its findings
    were there before, so they block nobody, baseline or not."""
    git_repo.commit({"s3.tf": "bucket\n"})
    git_repo.stage({"s3.tf": "# typo fixed\nbucket\n"})
    scanner = Scanner(now=[finding("bucket", "s3.tf")], earlier=[finding("bucket", "s3.tf")])
    code, result = hook(git_repo, scanner, "s3.tf")

    assert code == 0
    assert (result["findings"], result["preexisting_count"]) == ([], 1)
    assert result["compared_label"].endswith("the last commit")


def test_the_earlier_version_of_a_push_is_where_it_leaves_the_remote(git_repo):
    """pre-commit takes a push's files from FROM...TO, which is the merge
    base, so the comparison is with that commit, not with where the remote
    has moved on to since."""
    fork = git_repo.commit({"main.tf": "a\n"})
    git_repo.git("checkout", "-q", "-b", "remote")
    remote = git_repo.commit({"other.tf": "the remote moved on\n"})
    git_repo.git("checkout", "-q", "-")
    pushed = git_repo.commit({"main.tf": "b\n"})
    _, result = hook(git_repo, Scanner(), "main.tf", env=push(remote, pushed))
    assert result["compared_with"] == fork


def test_an_untracked_file_beside_a_changed_one_is_outside_the_change(git_repo):
    git_repo.commit({"main.tf": "a\n"})
    git_repo.stage({"main.tf": "b\n"})
    git_repo.write({"scratch.tf": "never added\n"})
    code, result = hook(git_repo, Scanner(now=[finding("scratch", "scratch.tf")]), "main.tf")
    assert code == 0
    assert (result["outside_changes_count"], result["preexisting_count"]) == (1, 0)


def test_the_baseline_still_applies_to_what_a_change_brought(git_repo):
    git_repo.commit({"main.tf": "a\n"})
    (git_repo.path / ".cascadesec-baseline.json").write_text(json.dumps(
        {"version": 1, "scanner_image": "img:1", "findings": [{"fingerprint": "accepted"}]}))
    git_repo.stage({"main.tf": "b\n"})
    _, result = hook(git_repo, Scanner(now=[finding("accepted", "main.tf"), finding("new", "main.tf")]),
                     "main.tf")
    assert fingerprints(result) == ["new"] and result["baselined_count"] == 1


def test_files_that_are_not_a_staged_change_are_judged_themselves(git_repo):
    """`pre-commit run --all-files` passes committed files with nothing
    staged. There is no change to compare, so every finding in the files
    counts: comparing with HEAD would pass everything, and say nothing."""
    git_repo.commit({"s3.tf": "bucket\n", "other.tf": "x\n"})
    scanner = Scanner(now=[finding("bucket", "s3.tf"), finding("o", "other.tf")])
    code, result = hook(git_repo, scanner, "s3.tf")

    assert code == 1 and fingerprints(result) == ["bucket"]
    assert result["compared_with"] is None and "--all-files" in result["not_compared_reason"]
    assert scanner.exported == []                       # one scan, not two


def test_a_first_commit_has_nothing_to_compare_with(git_repo):
    git_repo.stage({"s3.tf": "bucket\n"})
    code, result = hook(git_repo, Scanner(now=[finding("bucket", "s3.tf")]), "s3.tf")
    assert code == 1 and "first commit" in result["not_compared_reason"]


def test_outside_a_repository_it_says_git_could_not_read_it(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    monkeypatch.setattr("cascadesec.scan.shutil.which", lambda name: "/usr/bin/docker")
    out = io.StringIO()
    cli.main(["--format", "json", "hook", "s3.tf"], stdout=out, env=ENV, cwd=tmp_path, run=Scanner())
    assert "git could not read" in json.loads(out.getvalue())["not_compared_reason"]


def test_a_worktree_whose_history_is_out_of_reach_says_which_hook_can_compare(tmp_path, monkeypatch):
    """Inside the docker hook's container, a worktree's .git names a gitdir
    on the host that the mount does not include."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    monkeypatch.setattr("cascadesec.scan.shutil.which", lambda name: "/usr/bin/docker")
    (tmp_path / ".git").write_text("gitdir: /host/only/.git/worktrees/wt\n")
    out = io.StringIO()
    cli.main(["--format", "json", "hook", "s3.tf"], stdout=out, env=ENV, cwd=tmp_path, run=Scanner())
    assert "worktree" in json.loads(out.getvalue())["not_compared_reason"]


def test_the_table_says_what_it_compared_with(git_repo):
    git_repo.commit({"s3.tf": "bucket\n"})
    git_repo.stage({"s3.tf": "# typo\nbucket\n"})
    _, out = hook(git_repo, Scanner(now=[finding("bucket", "s3.tf")], earlier=[finding("bucket", "s3.tf")]),
                  "s3.tf", fmt="table")
    text = " ".join(out.split())
    assert "0 new with this change" in text
    assert "the last commit: 1 finding was already there, left out." in text


def test_inside_the_image_the_earlier_version_is_scanned_in_process_too(git_repo, monkeypatch):
    base = git_repo.commit({"main.tf": "a\n", "variables.tf": "true\n"})
    pushed = git_repo.commit({"variables.tf": "false\n"})

    def local_scan(root, corpus, only_dirs):
        earlier = "cascadesec-earlier-" in str(root)
        return {"scanned_files": 2, "scan_errors": [], "unscanned_apps": [],
                "findings": [finding("old", "main.tf")] + ([] if earlier else [finding("opened", "main.tf")])}

    monkeypatch.setitem(sys.modules, "local_main",
                        types.SimpleNamespace(load_corpus=lambda: None, scan=local_scan))
    docker = Scanner()
    code, result = hook(git_repo, docker, "variables.tf", env={"CASCADESEC_IN_IMAGE": "1", **push(base, pushed)})
    assert docker.calls == []
    assert code == 1 and fingerprints(result) == ["opened"]


# ---------- scan --changed-only ----------

def test_changed_only_reports_what_the_change_brought_wherever_it_lands(git_repo):
    base = git_repo.commit({"main.tf": "bucket\n", "variables.tf": "default = true\n", "ec2.tf": "x\n"})
    git_repo.commit({"variables.tf": "default = false\n"})
    scanner = Scanner(now=[finding("old", "ec2.tf"), finding("opened", "main.tf")],
                      earlier=[finding("old", "ec2.tf")])
    code, result = scan(git_repo, scanner, "--changed-only", base)

    assert code == 1 and fingerprints(result) == ["opened"]
    assert (result["compared_with"], result["preexisting_count"]) == (base, 1)
    assert scanner.exported == [["ec2.tf", "main.tf", "variables.tf"]]     # the whole path, at REV


def test_changed_only_still_scopes_parse_errors_and_apps_to_changed_files(git_repo):
    base = git_repo.commit({"ec2.tf": "x\n", "old.tf": "y\n"})
    git_repo.write({"ec2.tf": "x2\n", "infra/new.ts": "untracked\n"})
    scanner = Scanner(errors=["ec2.tf", "old.tf"],
                      apps=[{"path": "infra", "kind": "cdk", "reason": "r"},
                            {"path": "chart", "kind": "helm", "reason": "r"}])
    _, result = scan(git_repo, scanner, "--changed-only", base)
    assert result["scan_errors"] == ["ec2.tf"]
    assert [a["path"] for a in result["unscanned_apps"]] == ["infra"]       # a new file inside it


def test_a_baselined_finding_left_out_as_old_is_not_reported_as_fixed(git_repo):
    base = git_repo.commit({"s3.tf": "bucket\n"})
    cli.main(["baseline", str(git_repo.path)], stdout=io.StringIO(), env=ENV, cwd=git_repo.path,
             run=Scanner(now=[finding("a", "s3.tf")]))
    _, result = scan(git_repo, Scanner(now=[finding("a", "s3.tf")], earlier=[finding("a", "s3.tf")]),
                     "--changed-only", base)
    assert (result["baseline_fixed"], result["preexisting_count"]) == ([], 1)


# ---------- the export ----------

def test_the_export_is_the_revisions_files_the_scanner_reads_directly_in_the_directories(git_repo, tmp_path_factory):
    rev = git_repo.commit({"infra/s3.tf": "then\n", "infra/vars.tfvars": "v\n", "infra/README.md": "r\n",
                           "infra/sub/deep.tf": "d\n", "main.tf": "m\n"})
    git_repo.write({"infra/s3.tf": "now\n"})
    dest = tmp_path_factory.mktemp("export")

    assert history.export(git_repo.path, rev, dest, dirs=["infra"]) == {"infra/s3.tf", "infra/vars.tfvars"}
    assert (dest / "infra" / "s3.tf").read_text() == "then\n"
    assert history.export(git_repo.path, rev, dest, dirs=["."]) == {"main.tf"}


def test_blob_bytes_come_through_the_batch_unchanged(git_repo, tmp_path_factory):
    files = {"a.tf": "two\nlines\n", "b.yaml": "no trailing newline", "c.json": "{}\n" * 300}
    rev = git_repo.commit(files)
    dest = tmp_path_factory.mktemp("export")
    history.export(git_repo.path, rev, dest)
    for name in files:
        blob = subprocess.run(["git", "-C", str(git_repo.path), "show", f"{rev}:{name}"],
                              capture_output=True, check=True).stdout
        assert (dest / name).read_bytes() == blob, name


def test_a_path_git_would_refuse_to_check_out_is_not_written():
    for bad in ("a/../../outside.tf", ".git/hooks/x.yaml", "a/.GIT/x.tf", "a//b.tf", "c:/x.tf"):
        assert not history._safe(bad), bad
    assert history._safe("infra/s3.tf")


def test_the_suffixes_exported_are_the_ones_the_scanner_reads():
    """An exported file the scanner ignores is waste; a file it reads and
    the export skips would make every finding in it look new."""
    source = (REPO / "lambda" / "iac-scanner" / "handler.py").read_text(encoding="utf-8")
    suffixes = ast.literal_eval(re.search(r"^SNAPSHOT_SUFFIXES = (\(.*?\))", source, re.S | re.M).group(1))
    assert set(history.ADMITTED) == {*suffixes, ".json", ".template"}
