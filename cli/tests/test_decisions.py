"""`approve`, `reject` and `edit` end to end, against a fake review-api at
the HTTP boundary (api._send) and a fake editor."""

import io
import json
from pathlib import Path

import pytest
from conftest import make_jwt

from cascadesec import api, editor
from cascadesec import main as cli
from cascadesec.store import SessionStore

PR = "gh-1388098412-5"
FIX = "aaaa000000000001"
DEPENDENT = "aaab000000000002"
RAW = "bbbb000000000003"
CONTENT = 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n'

FINDINGS = {
    FIX: {"finding_id": FIX, "source": "trivy", "rule_id": "AWS-0086", "file": "infra/s3.tf",
          "line_range": [1, 3], "status": "fix-proposed",
          "proposed_fix": {"diff": "+x\n", "self_check_passed": True}},
    DEPENDENT: {"finding_id": DEPENDENT, "source": "checkov", "rule_id": "CKV_AWS_18",
                "file": "infra/s3.tf", "status": "fix-proposed",
                "proposed_fix": {"diff": "+y\n", "applies_after": [{"finding_id": FIX, "diff_sha256": "0"}]}},
    RAW: {"finding_id": RAW, "source": "checkov", "rule_id": "CKV_AZURE_43", "file": "a.json",
          "status": "raw"},
}


class FakeApi:
    def __init__(self, content=CONTENT, review=None):
        self.content = content
        # finding_id -> (status, body) for POST .../review
        self.review = review or {}
        self.posts = []
        self.gets = []

    def __call__(self, method, url, token, body=None):
        parts = url.removeprefix("https://api.example.test/").split("/")
        assert parts[:2] == ["prs", PR], url
        if method == "POST":
            assert parts[2] == "findings" and parts[4] == "review", url
            self.posts.append((parts[3], body))
            return self.review.get(parts[3], (200, {
                "finding_id": parts[3], "action": body["action"],
                "status": "needs-human-only" if body["action"] == "rejected" else "resolved",
                "recorded_at": "2026-10-18T03:00:00+00:00", "reopened_dependents": []}))
        self.gets.append("/".join(parts[2:]))
        if parts[2:] == ["findings"]:
            return 200, {"pr_id": PR, "count": len(FINDINGS), "findings": list(FINDINGS.values())}
        if len(parts) == 4:
            f = FINDINGS.get(parts[3])
            return (200, f) if f else (404, {"error": "finding not found"})
        if parts[4:] == ["content"]:
            return 200, {"finding_id": parts[3], "file": FINDINGS[parts[3]]["file"], "content": self.content}
        return 404, {"error": "unknown route"}


@pytest.fixture
def env(tmp_path):
    return {"APPDATA": str(tmp_path / "a"), "XDG_CONFIG_HOME": str(tmp_path / "x"),
            "CASCADESEC_API": "https://api.example.test",
            "CASCADESEC_AUTH_DOMAIN": "auth.example.test", "CASCADESEC_CLIENT_ID": "client123"}


@pytest.fixture
def signed_in(backend):
    SessionStore("auth.example.test", "client123", backend=backend).save(
        {"id_token": make_jwt(exp=4_000_000_000), "refresh_token": "r", "expires_at": 4_000_000_000})


def run(argv, env, tmp_path, backend, fake, monkeypatch, **kwargs):
    monkeypatch.setattr(api, "_send", fake)
    out = io.StringIO()
    code = cli.main(argv, stdout=out, env=env, cwd=tmp_path, backend=backend, **kwargs)
    return code, out.getvalue()


class FakeEditor:
    """Stands in for subprocess.run(editor + [path]): rewrites the file the
    way a person would, and remembers where it was."""

    def __init__(self, change=lambda text: text.replace('"private"', '"log-delivery-write"'),
                 returncode=0, raw=None):
        self.change, self.returncode, self.raw = change, returncode, raw
        self.paths = []

    def __call__(self, command):
        path = Path(command[-1])
        self.paths.append(path)
        if self.raw is not None:
            path.write_bytes(self.raw(path.read_bytes()))
        else:
            path.write_bytes(self.change(path.read_bytes().decode("utf-8")).encode("utf-8"))
        return type("Done", (), {"returncode": self.returncode})()


# ---------- approve and reject ----------

def test_approve_posts_the_decision_and_says_what_it_did(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi()
    code, out = run(["--format", "table", "approve", PR, FIX, "--notes", "looks right"],
                    env, tmp_path, backend, fake, monkeypatch)

    assert code == 0
    assert fake.posts == [(FIX, {"action": "approved", "notes": "looks right"})]
    assert "Approved the fix for trivy AWS-0086 at infra/s3.tf:1-3" in out
    assert "Resolved" in out


def test_a_blocked_approval_names_each_unsettled_prerequisite(env, tmp_path, backend, signed_in,
                                                               monkeypatch, capsys):
    """The API's 409 carries every blocker at once; the CLI prints them all,
    in the server's words, rather than one generic refusal."""
    fake = FakeApi(review={DEPENDENT: (409, {
        "error": "fix depends on prerequisites that are not satisfied",
        "unmet": [{"finding_id": FIX, "reason": "rejected"},
                  {"finding_id": "cccc000000000009", "reason": "reopened"}]})})
    code, out = run(["approve", PR, DEPENDENT], env, tmp_path, backend, fake, monkeypatch)

    err = capsys.readouterr().err
    assert code == 1
    assert out == ""
    assert f"{FIX} was rejected" in err
    assert "cccc000000000009 was reopened by the system" in err
    assert f"cascadesec show {PR} {FIX}" in err
    assert f"cascadesec reject {PR} {DEPENDENT}` is never blocked" in err


def test_reject_reports_what_it_reopened(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi(review={FIX: (200, {"finding_id": FIX, "action": "rejected",
                                       "status": "needs-human-only", "recorded_at": "t",
                                       "reopened_dependents": [DEPENDENT]})})
    code, out = run(["--format", "table", "reject", PR, "aaaa", "--notes", "wrong bucket"],
                    env, tmp_path, backend, fake, monkeypatch)

    assert code == 0
    assert fake.posts == [(FIX, {"action": "rejected", "notes": "wrong bucket"})]
    assert "This reopened 1 finding" in out
    assert f"cascadesec show {PR} {DEPENDENT}" in out


def test_decision_json_names_the_reopened(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi(review={FIX: (200, {"action": "rejected", "status": "needs-human-only",
                                       "reopened_dependents": [DEPENDENT]})})
    _, out = run(["--format", "json", "reject", PR, FIX], env, tmp_path, backend, fake, monkeypatch)
    assert json.loads(out)["reopened_dependents"] == [DEPENDENT]


def test_a_refusal_with_only_a_reason_is_exit_1(env, tmp_path, backend, signed_in, monkeypatch, capsys):
    fake = FakeApi(review={RAW: (409, {"error": "finding has no proposed fix to act on"})})
    code, _ = run(["approve", PR, RAW], env, tmp_path, backend, fake, monkeypatch)
    assert code == 1
    assert "no proposed fix to act on" in capsys.readouterr().err


# ---------- edit ----------

def test_edit_sends_the_whole_saved_file_after_confirming(env, tmp_path, backend, signed_in, monkeypatch, capsys):
    fake, fake_editor, asked = FakeApi(), FakeEditor(), []
    code, out = run(["--format", "table", "edit", PR, FIX, "--notes", "needs log delivery"],
                    env, tmp_path, backend, fake, monkeypatch,
                    interactive=True, run=fake_editor, prompt=lambda q: asked.append(q) or "y")

    assert code == 0
    ((fid, body),) = fake.posts
    assert fid == FIX
    assert body == {"action": "edited", "notes": "needs log delivery",
                    "edited_content": CONTENT.replace('"private"', '"log-delivery-write"')}
    # The editor saw the file under its own name, for syntax highlighting.
    assert fake_editor.paths[0].name == "s3.tf"
    assert not fake_editor.paths[0].exists()   # cleaned up after success
    assert asked and "[y/N]" in asked[0]
    err = capsys.readouterr().err
    assert '-  acl = "private"' in err and '+  acl = "log-delivery-write"' in err
    assert "Recorded your edit" in out and "has not been through the scanner" in out


def test_saving_without_changes_records_nothing(env, tmp_path, backend, signed_in, monkeypatch, capsys):
    fake = FakeApi()
    code, out = run(["--format", "json", "edit", PR, FIX], env, tmp_path, backend, fake, monkeypatch,
                    interactive=True, run=FakeEditor(change=lambda t: t),
                    prompt=lambda q: pytest.fail("nothing to confirm"))

    assert code == 0
    assert fake.posts == []
    assert json.loads(out)["recorded"] is False
    assert "--wait" in capsys.readouterr().err


def test_declining_keeps_the_edit_on_disk(env, tmp_path, backend, signed_in, monkeypatch, capsys):
    fake, fake_editor = FakeApi(), FakeEditor()
    code, _ = run(["edit", PR, FIX], env, tmp_path, backend, fake, monkeypatch,
                  interactive=True, run=fake_editor, prompt=lambda q: "n")

    assert code == 0
    assert fake.posts == []
    assert fake_editor.paths[0].exists()
    assert str(fake_editor.paths[0]) in capsys.readouterr().err


def test_a_refused_edit_keeps_the_file_and_says_how_to_resend(env, tmp_path, backend, signed_in,
                                                               monkeypatch, capsys):
    fake = FakeApi(review={FIX: (400, {"error": "edited_content is identical to the fix's base; nothing to record"})})
    fake_editor = FakeEditor()
    code, _ = run(["edit", PR, FIX], env, tmp_path, backend, fake, monkeypatch,
                  interactive=True, run=fake_editor, prompt=lambda q: "y")

    err = capsys.readouterr().err
    assert code == 1
    assert "nothing to record" in err
    assert fake_editor.paths[0].exists()
    assert f"--file {fake_editor.paths[0]}" in err


def test_line_endings_survive_the_editor(env, tmp_path, backend, signed_in, monkeypatch):
    crlf = CONTENT.replace("\n", "\r\n")
    fake = FakeApi(content=crlf)
    run(["edit", PR, FIX, "--yes"], env, tmp_path, backend, fake, monkeypatch,
        interactive=True, run=FakeEditor())

    sent = fake.posts[0][1]["edited_content"]
    assert sent == crlf.replace('"private"', '"log-delivery-write"')


def test_a_bom_the_editor_added_is_not_the_persons_change(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi()
    run(["edit", PR, FIX, "--yes"], env, tmp_path, backend, fake, monkeypatch, interactive=True,
        run=FakeEditor(raw=lambda b: "﻿".encode() + b.replace(b"private", b"log-delivery-write")))

    assert not fake.posts[0][1]["edited_content"].startswith("﻿")


def test_a_failing_editor_records_nothing_and_keeps_the_file(env, tmp_path, backend, signed_in,
                                                              monkeypatch, capsys):
    fake, fake_editor = FakeApi(), FakeEditor(returncode=1)
    code, _ = run(["edit", PR, FIX], env, tmp_path, backend, fake, monkeypatch,
                  interactive=True, run=fake_editor, prompt=lambda q: "y")
    assert code == 2
    assert fake.posts == []
    assert fake_editor.paths[0].exists()


def test_a_prepared_file_needs_yes_without_a_terminal(env, tmp_path, backend, signed_in, monkeypatch):
    prepared = tmp_path / "fixed.tf"
    prepared.write_bytes(CONTENT.replace("private", "log-delivery-write").encode())

    fake = FakeApi()
    code, _ = run(["edit", PR, FIX, "--file", str(prepared)], env, tmp_path, backend, fake,
                  monkeypatch, interactive=False)
    assert (code, fake.posts) == (2, [])

    code, _ = run(["edit", PR, FIX, "--file", str(prepared), "--yes"], env, tmp_path, backend, fake,
                  monkeypatch, interactive=False)
    assert code == 0
    assert fake.posts[0][1]["edited_content"] == prepared.read_text()


def test_without_a_terminal_or_a_file_edit_refuses_before_fetching(env, tmp_path, backend, signed_in,
                                                                   monkeypatch):
    fake = FakeApi()
    code, _ = run(["edit", PR, FIX], env, tmp_path, backend, fake, monkeypatch, interactive=False)
    assert code == 2
    assert not any(g.endswith("content") for g in fake.gets)


def test_a_finding_with_no_fix_has_nothing_to_edit(env, tmp_path, backend, signed_in, monkeypatch):
    fake = FakeApi()
    code, _ = run(["edit", PR, RAW], env, tmp_path, backend, fake, monkeypatch, interactive=True)
    assert code == 1
    assert not any(g.endswith("content") for g in fake.gets)


# ---------- choosing the editor ----------

def test_visual_wins_then_editor_then_the_platform_default(monkeypatch):
    assert editor.editor_command({"VISUAL": "code --wait", "EDITOR": "vim"}) == ["code", "--wait"]
    assert editor.editor_command({"EDITOR": "nano"}) == ["nano"]
    monkeypatch.setattr(editor.os, "name", "nt")
    assert editor.editor_command({}) == ["notepad"]
    monkeypatch.setattr(editor.os, "name", "posix")
    assert editor.editor_command({}) == ["vi"]


def test_a_repository_path_never_becomes_a_local_path():
    draft = editor.Draft("../../etc/passwd", "x")
    try:
        assert draft.path.parent == draft.dir
        assert draft.path.name == "passwd"
    finally:
        draft.discard()
