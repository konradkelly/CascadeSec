"""The deploy guard. No terraform or AWS: `run` is faked, and the plans are
the JSON `terraform show -json` prints, trimmed to what the guard reads.

The two cases that earn the file are 2026-10-11's: a tfvars without the
writer App id must stop before any plan, and a plan that destroys
github-committer must be refused, not summarised and waved through."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import deploy  # noqa: E402

FULL_TFVARS = 'github_app_id = "5063017"\nalarm_email = "k@example.test"\ngithub_writer_app_id = "5132505"\n'


def change(address, *actions):
    return {"address": address, "change": {"actions": list(actions)}}


COMMITTER_DESTROYED = {"resource_changes": [
    change("aws_lambda_function.github_committer[0]", "delete"),
    change("aws_lambda_function.review_api", "update"),
    change("aws_cloudwatch_log_group.mapping_agent", "no-op"),
]}
RESTORE = {"resource_changes": [
    change("aws_lambda_function.github_committer[0]", "create"),
    change("aws_iam_role.github_committer[0]", "create"),
    change("aws_lambda_function.review_api", "update"),
    change("data.aws_kms_alias.github_writer_app[0]", "read"),
]}


@pytest.fixture
def root(tmp_path):
    (tmp_path / "terraform").mkdir()
    (tmp_path / "terraform" / "terraform.tfvars").write_text(FULL_TFVARS)
    return tmp_path


class FakeRun:
    """Answers git and terraform the way they would, from a canned plan."""

    def __init__(self, plan, git_ok=True, plan_ok=True):
        self.plan, self.git_ok, self.plan_ok = plan, git_ok, plan_ok
        self.calls = []

    def __call__(self, cmd, capture_output=False, text=False):
        self.calls.append(cmd)
        if cmd[0] == "git":
            return subprocess.CompletedProcess(cmd, 0 if self.git_ok else 128, b"", b"")
        verb = cmd[2]
        if verb == "plan":
            if self.plan_ok:
                Path(cmd[1].removeprefix("-chdir="), deploy.PLAN_FILE).write_text("binary plan")
            return subprocess.CompletedProcess(cmd, 0 if self.plan_ok else 1, "", "Error: No value for required variable")
        if verb == "show":
            return subprocess.CompletedProcess(cmd, 0, json.dumps(self.plan), "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def verbs(self):
        return [c[2] for c in self.calls if c[0] == "terraform"]


def run_main(root, plan, *args, **fake):
    runner, lines = FakeRun(plan, **fake), []
    code = deploy.main(["--terraform-dir", str(root / "terraform"), "--allow-local-changes", *args],
                       run=runner, out=lines.append)
    return code, runner, "\n".join(lines)


# ---------- 1. variables ----------

def test_the_missing_writer_app_id_stops_before_any_plan(root, capsys):
    (root / "terraform" / "terraform.tfvars").write_text('github_app_id = "5063017"\nalarm_email = "k@x"\n')

    code, runner, _ = run_main(root, RESTORE)

    assert code == 1
    assert runner.verbs() == []
    err = capsys.readouterr().err
    assert "github_writer_app_id" in err and "github-committer" in err


def test_no_tfvars_at_all_is_named_with_what_each_value_costs(root, capsys):
    (root / "terraform" / "terraform.tfvars").unlink()
    code, runner, _ = run_main(root, RESTORE)
    assert (code, runner.verbs()) == (1, [])
    err = capsys.readouterr().err
    assert all(name in err for name in deploy.REQUIRED_VARIABLES)


def test_tfvars_parsing_ignores_comments_and_quotes():
    values = deploy.tfvars_values('# github_writer_app_id = "x"\ngithub_app_id = "1" # the gateway\n'
                                  'alarm_email="a@b" // inline\nempty = ""\n')
    assert values == {"github_app_id": "1", "alarm_email": "a@b", "empty": ""}


def test_an_empty_value_counts_as_unset(root, capsys):
    (root / "terraform" / "terraform.tfvars").write_text(FULL_TFVARS.replace('"5132505"', '""'))
    code, _, _ = run_main(root, RESTORE)
    assert code == 1
    assert "github_writer_app_id" in capsys.readouterr().err


# ---------- 3, 4. the plan ----------

def test_a_plan_that_destroys_the_committer_is_refused(root, capsys):
    code, runner, out = run_main(root, COMMITTER_DESTROYED)

    assert code == 1
    assert runner.verbs() == ["plan", "show"]          # never apply
    assert "1 destroy" in out
    err = capsys.readouterr().err
    assert "aws_lambda_function.github_committer[0]" in err and "--allow-destroy" in err


def test_a_named_destroy_is_allowed_and_only_that_one(root):
    code, _, _ = run_main(root, COMMITTER_DESTROYED,
                          "--allow-destroy", "aws_lambda_function.github_committer[0]")
    assert code == 0

    plan = {"resource_changes": COMMITTER_DESTROYED["resource_changes"]
            + [change("aws_s3_bucket.artifacts", "delete")]}
    code, _, _ = run_main(root, plan, "--allow-destroy", "aws_lambda_function.github_committer[0]")
    assert code == 1


def test_a_replace_is_a_destroy(root):
    code, _, _ = run_main(root, {"resource_changes": [
        change("aws_lambda_function.review_api", "delete", "create")]})
    assert code == 1


def test_the_restore_plan_passes_and_says_what_it_does(root):
    code, runner, out = run_main(root, RESTORE)

    assert code == 0
    assert runner.verbs() == ["plan", "show"]
    assert "plan: 2 creates, 1 update, 0 replaces, 0 destroys" in out
    assert "+ aws_lambda_function.github_committer[0]" in out
    assert "--apply-saved" in out


def test_the_plan_never_prompts_for_a_variable(root):
    _, runner, _ = run_main(root, RESTORE)
    plan_call = next(c for c in runner.calls if c[0] == "terraform" and c[2] == "plan")
    assert "-input=false" in plan_call


def test_a_failed_plan_stops(root, capsys):
    code, runner, _ = run_main(root, RESTORE, plan_ok=False)
    assert code == 1
    assert "show" not in runner.verbs()


# ---------- applying the reviewed plan ----------

def test_apply_saved_checks_the_saved_plan_again_then_applies_it(root):
    run_main(root, RESTORE)
    code, runner, _ = run_main(root, RESTORE, "--apply-saved")

    assert code == 0
    apply_call = next(c for c in runner.calls if c[0] == "terraform" and c[2] == "apply")
    assert apply_call[-1] == deploy.PLAN_FILE and "-input=false" in apply_call
    assert not (root / "terraform" / deploy.PLAN_FILE).exists()


def test_apply_saved_refuses_a_saved_plan_that_destroys(root):
    (root / "terraform" / deploy.PLAN_FILE).write_text("binary plan")
    code, runner, _ = run_main(root, COMMITTER_DESTROYED, "--apply-saved")
    assert code == 1
    assert "apply" not in runner.verbs()


def test_apply_saved_needs_a_saved_plan(root):
    code, runner, _ = run_main(root, RESTORE, "--apply-saved")
    assert (code, runner.verbs()) == (1, [])


# ---------- 2. the packaged code ----------

def test_packaged_code_that_differs_from_the_ref_is_named(tmp_path):
    (tmp_path / "terraform").mkdir()
    (tmp_path / "terraform" / "main.tf").write_bytes(b'resource "x" "y" {}\r\n')
    (tmp_path / "lambda" / "review-api").mkdir(parents=True)
    (tmp_path / "lambda" / "review-api" / "handler.py").write_bytes(b"print('edited')\n")
    committed = {"terraform/main.tf": b'resource "x" "y" {}\n', "lambda/review-api/handler.py": b"print('main')\n"}

    def git(cmd, capture_output=True):
        path = cmd[-1].split(":", 1)[1]
        return subprocess.CompletedProcess(cmd, 0, committed[path], b"")

    with pytest.raises(deploy.Stop) as e:
        deploy.check_code(tmp_path, "origin/main", git=git)
    message = str(e.value)
    assert "lambda/review-api/handler.py" in message
    assert "terraform/main.tf" not in message            # CRLF alone is not a difference
