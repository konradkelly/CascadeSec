"""`cascadesec commit` end to end: the plan printed before any question, a
confirmation built only from what was printed, and the wait on the
committer -- against a fake review-api at the HTTP boundary."""

import copy
import io
import json

import pytest
from conftest import make_jwt

from cascadesec import api, commit
from cascadesec import main as cli
from cascadesec.errors import CliError
from cascadesec.store import SessionStore

PR = "gh-1388098412-5"
SHA = "a" * 64

PLAN = {
    "pr_id": PR, "repository": "konradkelly/cascadesec-testbed", "pr_number": 5, "preview": True,
    "write_back_deployed": True, "can_commit": True,
    "counts": {"commit": 1, "already": 0, "held": 1},
    "files": [
        {"file": "infra/lib/network.ts", "outcome": "commit", "reason": None,
         "tip": "e0697165490061ed", "content_sha256": SHA, "left_out": [],
         "chain": [{"finding_id": "e0697165490061ed", "rule_id": "AWS-0164", "verified": True,
                    "edited": False}],
         "diff": "--- a/infra/lib/network.ts\n+++ b/infra/lib/network.ts\n-mapPublicIpOnLaunch: true\n+mapPublicIpOnLaunch: false\n"},
        {"file": "infra/lib/storage.ts", "outcome": "held", "tip": "bd4c4900f58c5fbc",
         "reason": "the file has changed since these fixes were drafted; run Draft fixes again",
         "content_sha256": None, "left_out": [], "chain": [], "diff": None},
    ],
    "latest_request": None,
}


class FakeApi:
    def __init__(self, plan=PLAN, post=None, statuses=("committing", "committed"), final=None):
        self.plan = copy.deepcopy(plan)
        self.post = post or (202, {"request_id": "01REQ", "status": "requested"})
        self.statuses = list(statuses)
        self.final = final or {"commit_sha": "c0ffee1234567", "files": [
            {"file": "infra/lib/network.ts", "outcome": "committed", "reason": None,
             "tip": "e0697165490061ed", "unverified": [], "left_out": []}]}
        self.posts, self.polls = [], 0

    def __call__(self, method, url, token, body=None):
        parts = url.removeprefix("https://api.example.test/").split("/")
        assert parts[:2] == ["prs", PR], url
        if parts[2:] == ["commit-plan"]:
            return 200, self.plan
        if method == "POST" and parts[2:] == ["commits"]:
            self.posts.append(body)
            return self.post
        if parts[2] == "commits" and len(parts) == 4:
            status = self.statuses[min(self.polls, len(self.statuses) - 1)]
            self.polls += 1
            record = {"request_id": parts[3], "status": status, "requested_by": "k@example.test"}
            return 200, {**record, **(self.final if status not in commit.ACTIVE else {})}
        return 404, {"error": "unknown route"}


@pytest.fixture
def env(tmp_path):
    return {"APPDATA": str(tmp_path / "a"), "XDG_CONFIG_HOME": str(tmp_path / "x"),
            "CASCADESEC_API": "https://api.example.test",
            "CASCADESEC_AUTH_DOMAIN": "auth.example.test", "CASCADESEC_CLIENT_ID": "client123"}


@pytest.fixture
def signed_in(backend):
    SessionStore("auth.example.test", "client123", backend=backend).save({
        "id_token": make_jwt(exp=4_000_000_000, email="k@example.test", **{"cognito:groups": ["committers"]}),
        "refresh_token": "r", "expires_at": 4_000_000_000})


class Clock:
    def __init__(self):
        self.t, self.slept = 0.0, []

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.t += seconds

    def now(self):
        return self.t


def run(argv, env, tmp_path, backend, fake, monkeypatch, clock=None, **kwargs):
    monkeypatch.setattr(api, "_send", fake)
    clock = clock or Clock()
    out = io.StringIO()
    code = cli.main(argv, stdout=out, env=env, cwd=tmp_path, backend=backend,
                    sleep=clock.sleep, clock=clock.now, **kwargs)
    return code, out.getvalue()


# ---------- the plan, and refusals it already implies ----------

def test_commits_exactly_what_the_printed_plan_shows(env, tmp_path, backend, signed_in, monkeypatch, capsys):
    fake, asked = FakeApi(), []
    code, out = run(["--format", "table", "commit", PR], env, tmp_path, backend, fake, monkeypatch,
                    interactive=True, prompt=lambda q: asked.append(q) or "y")

    err = capsys.readouterr().err
    assert code == 0
    # Printed before the question: the diff, the hash, and what is held and why.
    assert "+mapPublicIpOnLaunch: false" in err
    assert f"sha256  {SHA}" in err
    assert "infra/lib/storage.ts: held" in err and "run Draft fixes again" in err
    assert "Commit 1 file to konradkelly/cascadesec-testbed#5, as shown? [y/N]" in asked[0]
    # Only the committable file, with the tip and hash that were printed.
    assert fake.posts == [{"confirm": [{"file": "infra/lib/network.ts", "tip": "e0697165490061ed",
                                        "content_sha256": SHA}]}]
    assert "Commit request 01REQ: committed in c0ffee1" in out
    assert "https://github.com/konradkelly/cascadesec-testbed/commit/c0ffee1234567" in out


def test_not_a_committer_is_told_before_any_prompt(env, tmp_path, backend, monkeypatch, capsys):
    SessionStore("auth.example.test", "client123", backend=backend).save({
        "id_token": make_jwt(exp=4_000_000_000, email="r@example.test"), "refresh_token": "r",
        "expires_at": 4_000_000_000})
    fake = FakeApi(plan={**PLAN, "can_commit": False})
    code, _ = run(["commit", PR], env, tmp_path, backend, fake, monkeypatch, interactive=True,
                  prompt=lambda q: pytest.fail("must not ask a non-committer"))

    err = capsys.readouterr().err
    assert code == 1
    assert fake.posts == []
    assert "+mapPublicIpOnLaunch: false" in err          # still shown the plan
    assert "r@example.test is not in it" in err and "cascadesec login" in err


@pytest.mark.parametrize("plan,words", [
    ({**PLAN, "write_back_deployed": False}, "not deployed"),
    ({**PLAN, "latest_request": {"request_id": "01OLD", "status": "committing", "requested_by": "x"}},
     "01OLD for this PR is still committing"),
])
def test_other_refusals_the_plan_implies(env, tmp_path, backend, signed_in, monkeypatch, capsys, plan, words):
    fake = FakeApi(plan=plan)
    code, _ = run(["commit", PR, "--yes"], env, tmp_path, backend, fake, monkeypatch, interactive=True)
    assert code == 1
    assert fake.posts == []
    assert words in capsys.readouterr().err


def test_nothing_approved_is_nothing_to_commit(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi(plan={**PLAN, "files": [PLAN["files"][1]]})
    code, out = run(["--format", "json", "commit", PR], env, tmp_path, backend, fake, monkeypatch,
                    interactive=True, prompt=lambda q: pytest.fail("nothing to confirm"))
    assert code == 0
    assert json.loads(out)["status"] == "nothing-to-commit"
    assert fake.posts == []


def test_declining_commits_nothing(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi()
    code, _ = run(["commit", PR], env, tmp_path, backend, fake, monkeypatch,
                  interactive=True, prompt=lambda q: "n")
    assert (code, fake.posts) == (0, [])


def test_a_plan_that_moved_is_reported_not_retried(env, tmp_path, backend, signed_in, monkeypatch, capsys):
    fake = FakeApi(post=(409, {"error": "the commit plan has changed since it was shown; review it again",
                               "changed": ["infra/lib/network.ts"]}))
    code, _ = run(["commit", PR, "--yes"], env, tmp_path, backend, fake, monkeypatch, interactive=True)

    err = capsys.readouterr().err
    assert code == 1
    assert len(fake.posts) == 1          # one attempt, never a silent second one
    assert "changed after it was shown (infra/lib/network.ts)" in err
    assert f"cascadesec commit {PR}" in err


# ---------- without a terminal ----------

def test_without_a_terminal_yes_alone_is_not_enough(env, tmp_path, backend, signed_in, monkeypatch, capsys):
    fake = FakeApi()
    code, _ = run(["commit", PR, "--yes"], env, tmp_path, backend, fake, monkeypatch, interactive=False)
    assert code == 2
    assert fake.posts == []
    assert "--expect-sha" in capsys.readouterr().err


def test_a_script_commits_only_the_content_it_names(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi()
    code, out = run(["--format", "json", "commit", PR, "--yes", "--expect-sha",
                     f"infra/lib/network.ts={SHA}"], env, tmp_path, backend, fake, monkeypatch,
                    interactive=False)

    assert code == 0
    assert len(fake.posts) == 1
    result = json.loads(out)
    assert (result["status"], result["commit_sha"]) == ("committed", "c0ffee1234567")
    assert not any(k.startswith("_") for k in result)


@pytest.mark.parametrize("expect,words", [
    ([f"infra/lib/network.ts={'b' * 64}"], f"would commit {SHA}, not {'b' * 64}"),
    ([f"infra/lib/network.ts={SHA}", f"other.tf={SHA}"], "other.tf was expected"),
    ([f"other.tf={SHA}"], "infra/lib/network.ts would be committed, and was not expected"),
])
def test_a_plan_unlike_the_expectation_is_refused(env, tmp_path, backend, signed_in, monkeypatch,
                                                  capsys, expect, words):
    fake = FakeApi()
    argv = ["commit", PR, "--yes"] + [a for e in expect for a in ("--expect-sha", e)]
    code, _ = run(argv, env, tmp_path, backend, fake, monkeypatch, interactive=False)
    assert code == 1
    assert fake.posts == []
    assert words in capsys.readouterr().err


@pytest.mark.parametrize("bad", ["network.ts", "network.ts=abc", f"={SHA}", "f=" + "g" * 64])
def test_a_malformed_expectation_is_a_usage_error(bad):
    with pytest.raises(CliError) as e:
        commit.parse_expect([bad])
    assert e.value.code == 2


# ---------- waiting on the committer ----------

def test_a_held_request_exits_1_with_its_reasons(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi(statuses=("committing", "held"), final={
        "reason": "nothing could be committed; see each file", "files": [
            {"file": "infra/lib/network.ts", "outcome": "held",
             "reason": "the branch moved since the plan was made", "unverified": []}]})
    code, out = run(["--format", "table", "commit", PR, "--yes"], env, tmp_path, backend, fake,
                    monkeypatch, interactive=True)
    assert code == 1
    assert "Commit request 01REQ: held" in out
    assert "the branch moved since the plan was made" in out


def test_a_failed_request_is_a_service_error(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi(statuses=("failed",), final={"reason": "the request could not be handed to the committer"})
    code, _ = run(["commit", PR, "--yes"], env, tmp_path, backend, fake, monkeypatch, interactive=True)
    assert code == 4


def test_polling_backs_off_to_a_cap(env, tmp_path, backend, signed_in, monkeypatch):
    clock = Clock()
    fake = FakeApi(statuses=["requested"] * 6 + ["committed"])
    code, _ = run(["commit", PR, "--yes"], env, tmp_path, backend, fake, monkeypatch, clock=clock,
                  interactive=True)
    assert code == 0
    assert clock.slept == [2, 4, 8, 15, 15, 15]


def test_a_timeout_names_the_request_and_leaves_it_running(env, tmp_path, backend, signed_in,
                                                          monkeypatch, capsys):
    fake = FakeApi(statuses=["committing"])
    code, _ = run(["commit", PR, "--yes", "--timeout", "20"], env, tmp_path, backend, fake,
                  monkeypatch, interactive=True)
    assert code == 4
    assert "01REQ is still committing after 20s" in capsys.readouterr().err


def test_no_wait_returns_once_recorded(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi()
    code, out = run(["--format", "json", "commit", PR, "--yes", "--no-wait"], env, tmp_path, backend,
                    fake, monkeypatch, interactive=True)
    assert code == 0
    assert json.loads(out)["request_id"] == "01REQ"
    assert fake.polls == 0


def test_a_manual_run_has_no_branch_to_commit_to(env, tmp_path, backend, signed_in, monkeypatch, capsys):
    monkeypatch.setattr(api, "_send", lambda *a, **k: (404, {
        "error": "not a GitHub pull request, or not scanned since write-back was deployed; push to it once"}))
    code = cli.main(["commit", "manual-test-1"], stdout=io.StringIO(), env=env, cwd=tmp_path, backend=backend)
    assert code == 2
    assert "not a GitHub pull request" in capsys.readouterr().err
