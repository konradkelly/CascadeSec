"""`findings` and `show` end to end: argv in, review-api faked at the HTTP
boundary (api._send), text or JSON out."""

import io
import json

import pytest
from conftest import make_jwt

from cascadesec import api
from cascadesec import main as cli
from cascadesec.store import SessionStore

PR = "gh-1388098412-5"
GOOD_DIFF = "--- a/s3.tf\n+++ b/s3.tf\n@@ -1 +1 @@\n-acl = \"public-read\"\n+acl = \"private\"\n"

FINDINGS = [
    {"finding_id": "aaaa000000000001", "source": "trivy", "rule_id": "AWS-0086", "file": "s3.tf",
     "line_range": [3, 9], "severity": "HIGH", "status": "fix-proposed",
     "control_mappings": [{"framework": "CIS-AWS-1.4", "control_id": "2.1.5",
                           "citation_span": "Block public access", "rationale": "AWS-0086 is it."}],
     "proposed_fix": {"diff": GOOD_DIFF, "rationale": "Make the bucket private.",
                      "self_check_passed": True, "cleared": True}},
    {"finding_id": "aaaa000000000002", "source": "checkov", "rule_id": "CKV_AWS_18", "file": "s3.tf",
     "severity": "MEDIUM", "status": "needs-human-only",
     "proposed_fix": {"diff": GOOD_DIFF + "+logging {}\n", "self_check_passed": False, "cleared": True,
                      "assumptions": ["a log bucket exists"],
                      "applies_after": [{"finding_id": "aaaa000000000001",
                                         "diff_sha256": "0" * 64}]}},
    {"finding_id": "bbbb000000000003", "source": "checkov", "rule_id": "CKV_AZURE_43",
     "title": "Ensure Storage Accounts adhere to the naming rules", "file": "a.json",
     "status": "raw", "unmapped_reason": "hygiene"},
    {"finding_id": "bbbb000000000004", "source": "checkov", "rule_id": "CKV_AZURE_43", "file": "b.json",
     "status": "raw", "unmapped_reason": "hygiene"},
    {"finding_id": "cccc000000000005", "source": "trivy", "rule_id": "KSV-0020", "file": "k8s/app.yaml",
     "severity": "LOW", "status": "raw"},
]
EVENTS = [{"action": "edited", "actor": "r@example.test", "notes": "kept logging off",
           "created_at": "2026-10-16T10:00:00+00:00"}]


class FakeApi:
    def __init__(self, findings=FINDINGS):
        self.findings = {f["finding_id"]: f for f in findings}
        self.calls = []

    def __call__(self, method, url, token, body=None):
        path = url.removeprefix("https://api.example.test/")
        self.calls.append(path)
        parts = path.split("/")
        if parts[0] != "prs" or parts[1] != PR:
            return 200, {"pr_id": parts[1], "count": 0, "findings": []}
        if parts[2:] == ["findings"]:
            return 200, {"pr_id": PR, "count": len(self.findings), "findings": list(self.findings.values())}
        if len(parts) == 4:
            f = self.findings.get(parts[3])
            return (200, f) if f else (404, {"error": "finding not found"})
        if parts[4:] == ["events"]:
            return 200, {"finding_id": parts[3], "count": len(EVENTS), "events": EVENTS}
        return 404, {"error": "unknown route"}


@pytest.fixture
def env(tmp_path):
    return {"APPDATA": str(tmp_path / "a"), "XDG_CONFIG_HOME": str(tmp_path / "x"),
            "CASCADESEC_API": "https://api.example.test",
            "CASCADESEC_AUTH_DOMAIN": "auth.example.test", "CASCADESEC_CLIENT_ID": "client123"}


@pytest.fixture
def fake(monkeypatch, backend):
    SessionStore("auth.example.test", "client123", backend=backend).save(
        {"id_token": make_jwt(exp=4_000_000_000), "refresh_token": "r", "expires_at": 4_000_000_000})
    fake = FakeApi()
    monkeypatch.setattr(api, "_send", fake)
    return fake


def run(argv, env, tmp_path, backend):
    out = io.StringIO()
    return cli.main(argv, stdout=out, env=env, cwd=tmp_path, backend=backend), out.getvalue()


# ---------- findings ----------

def test_findings_table_groups_as_the_dashboard_does(fake, env, tmp_path, backend):
    code, out = run(["--format", "table", "findings", PR], env, tmp_path, backend)

    assert code == 0
    assert out.splitlines()[0] == f"{PR} - 5 findings - 2 mapped to a control (40%)"
    to_review = out.index("Fixes to review (2)")
    raw = out.index("Reported by the scanner, no control mapped (3)")
    assert to_review < out.index("aaaa000000000001") < raw
    assert "Self-check passed" in out and "Rescan clean, held for review" in out
    # Raw: one row per rule, the backlog-ish group (never examined) before the decided one.
    assert out.index("Not examined") < out.index("Hygiene, not a security control")
    assert "2 in 2 files" in out
    assert "bbbb000000000003" not in out


def test_findings_json_is_the_apis_records_filtered(fake, env, tmp_path, backend):
    code, out = run(["--format", "json", "findings", PR, "--status", "raw", "--file", "*.json"],
                    env, tmp_path, backend)

    result = json.loads(out)
    assert code == 0
    assert (result["count"], result["matched"]) == (5, 2)
    assert {f["finding_id"] for f in result["findings"]} == {"bbbb000000000003", "bbbb000000000004"}
    assert not any(k.startswith("_") for k in result)


def test_an_unknown_pr_is_empty_and_says_so(fake, env, tmp_path, backend, capsys):
    code, out = run(["--format", "json", "findings", "gh-1-1"], env, tmp_path, backend)
    assert code == 0
    assert json.loads(out)["count"] == 0
    assert "check the id" in capsys.readouterr().err


def test_not_signed_in_is_exit_4_before_any_request(env, tmp_path, backend, monkeypatch):
    monkeypatch.setattr(api, "_send", lambda *a, **k: pytest.fail("no request without a session"))
    code, _ = run(["findings", PR], env, tmp_path, backend)
    assert code == 4


# ---------- show ----------

def test_show_prints_controls_fix_gates_prerequisites_and_history(fake, env, tmp_path, backend):
    code, out = run(["--format", "table", "show", PR, "aaaa000000000002"], env, tmp_path, backend)

    assert code == 0
    assert "Rescan clean, held for review" in out
    assert "a log bucket exists" in out
    # Its prerequisite is still awaiting a decision, as the dashboard would say.
    assert "aaaa000000000001 (has not been accepted yet)" in out
    assert "+logging {}" in out
    assert "kept logging off" in out
    assert "\033[" not in out  # not a terminal: no colour


def test_show_accepts_a_unique_prefix(fake, env, tmp_path, backend):
    code, out = run(["--format", "json", "show", PR, "cccc"], env, tmp_path, backend)

    result = json.loads(out)
    assert code == 0
    assert result["finding"]["rule_id"] == "KSV-0020"
    assert result["unmet_prerequisites"] == []


def test_an_ambiguous_prefix_lists_the_candidates(fake, env, tmp_path, backend, capsys):
    code, _ = run(["show", PR, "aaaa"], env, tmp_path, backend)
    assert code == 2
    assert "matches 2 findings" in capsys.readouterr().err


def test_an_unknown_finding_is_a_usage_error(fake, env, tmp_path, backend, capsys):
    code, _ = run(["show", PR, "ffffffffffffffff"], env, tmp_path, backend)
    assert code == 2
    assert f"{PR} has no finding ffffffffffffffff" in capsys.readouterr().err


def test_a_raw_finding_shows_why_it_is_raw(fake, env, tmp_path, backend):
    code, out = run(["--format", "table", "show", PR, "bbbb000000000003"], env, tmp_path, backend)
    assert code == 0
    assert "Hygiene, not a security control" in out
    assert "No fix" in out


def test_a_full_id_is_fetched_directly_without_the_listing(fake, env, tmp_path, backend):
    run(["--format", "json", "show", PR, "aaaa000000000001"], env, tmp_path, backend)
    assert f"prs/{PR}/findings" not in fake.calls
