"""Tests for github-gateway's handler. KMS, S3, DynamoDB and GitHub are all
mocked -- no AWS or network calls."""

import base64
import hashlib
import io
import json
import tarfile
from unittest.mock import MagicMock, patch

import pytest

import handler


HEAD = "a" * 40
GITHUB = {
    "installation_id": 987, "repository_id": 123456, "repository": "o/r",
    "pr_number": 7, "head_sha": HEAD, "base_sha": "b" * 40, "trigger": "push",
}
ARM = b'{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"}'


def _tarball(members):
    """A gzipped tarball shaped like GitHub's: everything under one top dir.
    members: (name, data) for a file, or (name, TarInfo type, linkname)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for m in members:
            info = tarfile.TarInfo(m[0])
            if len(m) == 2:
                info.size = len(m[1])
                tar.addfile(info, io.BytesIO(m[1]))
            else:
                info.type, info.linkname = m[1], m[2]
                tar.addfile(info)
    buf.seek(0)
    return buf


def _b64decode(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


# ======================================================================
# the App's identity
# ======================================================================

def test_jwt_is_signed_by_kms_over_header_and_claims():
    with patch.object(handler, "kms") as kms, patch.object(handler, "GITHUB_APP_ID", "4242"), \
            patch.object(handler, "KMS_KEY_ID", "alias/test"):
        kms.sign.return_value = {"Signature": b"sig-bytes"}
        token = handler.app_jwt(now=1_000_000)

    header, claims, signature = token.split(".")
    assert json.loads(_b64decode(header)) == {"alg": "RS256", "typ": "JWT"}
    assert json.loads(_b64decode(claims)) == {"iat": 999_940, "exp": 1_000_540, "iss": 4242}
    assert _b64decode(signature) == b"sig-bytes"
    kwargs = kms.sign.call_args.kwargs
    assert kwargs["Message"] == f"{header}.{claims}".encode()
    assert kwargs["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"
    assert kwargs["KeyId"] == "alias/test"


def test_jwt_expiry_is_inside_githubs_ten_minutes():
    with patch.object(handler, "kms") as kms:
        kms.sign.return_value = {"Signature": b"s"}
        claims = json.loads(_b64decode(handler.app_jwt(now=0).split(".")[1]))
    assert claims["exp"] - claims["iat"] <= 600


def test_installation_token_is_narrowed_to_one_repository():
    with patch.object(handler, "app_jwt", return_value="jwt"), \
            patch.object(handler, "_request", return_value={"token": "t"}) as request:
        assert handler.installation_token(GITHUB, {"checks": "write"}) == "t"

    method, path, token, body = request.call_args.args
    assert (method, path, token) == ("POST", "/app/installations/987/access_tokens", "jwt")
    assert body == {"repository_ids": [123456], "permissions": {"checks": "write"}}


def test_tarball_redirect_is_not_followed_with_the_token():
    assert handler._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://x") is None


def test_next_link_is_parsed():
    link = '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"'
    assert handler._next_link(link) == "https://api.github.com/x?page=2"
    assert handler._next_link('<https://api.github.com/x?page=5>; rel="last"') is None


# ======================================================================
# the snapshot, and hostile archives
# ======================================================================

@pytest.mark.parametrize("name, expected", [
    ("o-r-sha/main.tf", "main.tf"),
    ("o-r-sha/k8s/base/app.yaml", "k8s/base/app.yaml"),
    ("o-r-sha/../../etc/passwd.tf", None),
    ("o-r-sha/a/../b.tf", None),
    ("o-r-sha/./b.tf", None),
    ("/abs/path.tf", None),
    ("o-r-sha/a\\..\\b.tf", None),
    ("o-r-sha//b.tf", None),
    ("toplevel-only", None),
])
def test_repo_path(name, expected):
    assert handler.repo_path(name) == expected


def test_snapshot_keeps_only_what_the_scanner_opens():
    kept = handler.read_snapshot(_tarball([
        ("o-r-sha/main.tf", b"resource {}"),
        ("o-r-sha/k8s/app.yaml", b"kind: Pod"),
        ("o-r-sha/azure/main.json", ARM),
        ("o-r-sha/package.json", b'{"name": "x"}'),
        ("o-r-sha/cfn/stack.template", b'{"AWSTemplateFormatVersion": "2010-09-09"}'),
        ("o-r-sha/README.md", b"# hi"),
        ("o-r-sha/src/app.py", b"print(1)"),
    ]))
    assert sorted(kept) == ["azure/main.json", "cfn/stack.template", "k8s/app.yaml", "main.tf"]
    assert kept["main.tf"] == b"resource {}"


def test_snapshot_skips_links_and_traversal():
    kept = handler.read_snapshot(_tarball([
        ("o-r-sha/ok.tf", b"x"),
        ("o-r-sha/link.tf", tarfile.SYMTYPE, "/etc/passwd"),
        ("o-r-sha/hard.tf", tarfile.LNKTYPE, "o-r-sha/ok.tf"),
        ("o-r-sha/../escape.tf", b"x"),
        ("/abs.tf", b"x"),
    ]))
    assert list(kept) == ["ok.tf"]


def test_snapshot_skips_the_same_directories_as_scan_py():
    kept = handler.read_snapshot(_tarball([
        ("o-r-sha/main.tf", b"x"),
        ("o-r-sha/.terraform/modules/m/main.tf", b"x"),
        ("o-r-sha/cdk.out/Stack.template.json", b'{"AWSTemplateFormatVersion": "x"}'),
        ("o-r-sha/node_modules/pkg/x.yaml", b"x"),
    ]))
    assert list(kept) == ["main.tf"]


def test_too_many_files_is_too_large_not_a_partial_snapshot():
    members = [(f"o-r-sha/f{i}.tf", b"x") for i in range(4)]
    with patch.object(handler, "MAX_SNAPSHOT_FILES", 3), pytest.raises(handler.TooLarge):
        handler.read_snapshot(_tarball(members))


def test_too_many_bytes_is_too_large():
    with patch.object(handler, "MAX_SNAPSHOT_BYTES", 10), pytest.raises(handler.TooLarge):
        handler.read_snapshot(_tarball([("o-r-sha/a.tf", b"x" * 6), ("o-r-sha/b.tf", b"x" * 6)]))


def test_tarball_over_the_download_cap_stops_reading():
    big = _tarball([("o-r-sha/a.tf", bytes(range(256)) * 400)])
    with pytest.raises(handler.TooLarge):
        handler.read_snapshot(handler._CappedReader(big, limit=100))


def test_replace_snapshot_removes_files_the_pr_deleted():
    with patch.object(handler, "s3") as s3:
        s3.get_paginator.return_value.paginate.return_value = [
            {"Contents": [{"Key": "scans/p/main.tf"}, {"Key": "scans/p/gone.tf"}]}]
        handler.replace_snapshot("p", {"main.tf": b"x", "new.tf": b"y"})

    put = sorted(c.kwargs["Key"] for c in s3.put_object.call_args_list)
    assert put == ["scans/p/main.tf", "scans/p/new.tf"]
    deleted = s3.delete_objects.call_args.kwargs["Delete"]["Objects"]
    assert deleted == [{"Key": "scans/p/gone.tf"}]


# ======================================================================
# fetch
# ======================================================================

@pytest.fixture
def github_calls():
    """_request stubbed: a check run is created with id 55."""
    with patch.object(handler, "installation_token", return_value="tok"), \
            patch.object(handler, "_request", return_value={"id": 55}) as request, \
            patch.object(handler, "_paginate") as paginate, \
            patch.object(handler, "s3") as s3:
        s3.get_paginator.return_value.paginate.return_value = [{}]
        yield request, paginate, s3


def _fetch_event(trigger="push"):
    return {"action": "fetch", "pr_id": "gh-123456-7", "execution_name": "exec-1",
            "github": {**GITHUB, "trigger": trigger}}


def test_fetch_opens_a_check_run_named_for_the_execution(github_calls):
    request, paginate, _ = github_calls
    paginate.return_value = []
    with patch.object(handler, "download_snapshot", return_value={"main.tf": b"x"}):
        handler.handler(_fetch_event(), None)

    method, path, _, body = request.call_args_list[0].args
    assert (method, path) == ("POST", "/repos/o/r/check-runs")
    assert body["head_sha"] == HEAD and body["status"] == "in_progress"
    assert body["external_id"] == "exec-1" and body["name"] == "CascadeSec"


def test_fetch_reports_changed_iac_files_only(github_calls):
    _, paginate, s3 = github_calls
    paginate.return_value = [
        {"filename": "main.tf", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"},
        {"filename": "old.tf", "status": "removed"},
        {"filename": "README.md", "status": "modified", "patch": "@@"},
    ]
    with patch.object(handler, "download_snapshot", return_value={"main.tf": b"x", "other.tf": b"y"}):
        result = handler.handler(_fetch_event(), None)

    assert result == {"status": "ok", "check_run_id": 55, "kept_count": 2,
                      "changed_files": ["main.tf"], "reason": None}
    stored = [c for c in s3.put_object.call_args_list if c.kwargs["Key"].startswith("github/")]
    assert stored[0].kwargs["Key"] == f"github/gh-123456-7/{HEAD}/files.json"


def test_fetch_too_large_scans_nothing(github_calls):
    _, _, s3 = github_calls
    with patch.object(handler, "download_snapshot", side_effect=handler.TooLarge("big")):
        result = handler.handler(_fetch_event(), None)

    assert result["status"] == "too_large" and result["check_run_id"] == 55
    s3.put_object.assert_not_called()


def test_fetch_with_no_iac_files_is_empty(github_calls):
    with patch.object(handler, "download_snapshot", return_value={}):
        assert handler.handler(_fetch_event(), None)["status"] == "empty"


# ======================================================================
# select_files
# ======================================================================

def test_select_files_takes_changed_files_with_mapped_findings():
    findings = [
        {"file": "a.tf", "status": "mapped"},
        {"file": "b.tf", "status": "mapped"},             # not changed
        {"file": "c.tf", "status": "raw"},                # not mapped
        {"file": "d.tf", "status": "mapped", "no_longer_detected": "t"},
    ]
    with patch.object(handler, "query_findings", return_value=findings):
        result = handler.handler({"action": "select_files", "pr_id": "p",
                                  "changed_files": ["a.tf", "c.tf", "d.tf"],
                                  "map": {"mapped_count": 0, "files": [], "remaining": 0}}, None)
    assert result["files"] == ["a.tf"]
    assert result["mapped_count"] == 0


# ======================================================================
# report: diff geometry
# ======================================================================

def test_diff_lines_tracks_added_and_visible_right_side_lines():
    patch_text = "@@ -10,4 +10,5 @@\n ctx\n-old\n+new1\n+new2\n ctx2\n@@ -40 +41 @@\n-x\n+y"
    added, visible = handler.diff_lines([{"filename": "f.tf", "status": "modified", "patch": patch_text}])
    assert added["f.tf"] == {11, 12, 41}
    assert visible["f.tf"] == {10, 11, 12, 13, 41}


def test_suggestion_hunks_replacement():
    assert handler.suggestion_hunks("a\nb\nc\n", "a\nB\nc\n") == [{"start": 2, "end": 2, "text": "B"}]


def test_suggestion_hunks_insertion_is_anchored_to_the_line_before():
    assert handler.suggestion_hunks("a\nb\n", "a\nnew\nb\n") == [{"start": 1, "end": 1, "text": "a\nnew"}]


def test_suggestion_hunks_insertion_at_top_is_anchored_to_the_first_line():
    assert handler.suggestion_hunks("a\n", "new\na\n") == [{"start": 1, "end": 1, "text": "new\na"}]


def test_suggestion_hunks_deletion_is_an_empty_suggestion():
    assert handler.suggestion_hunks("a\nb\nc\n", "a\nc\n") == [{"start": 2, "end": 2, "text": ""}]


def test_trailing_newline_difference_is_not_a_hunk():
    assert handler.suggestion_hunks("a\nb\n", "a\nb") == []


def test_suggestion_block_fence_outgrows_backticks_in_the_fix():
    assert handler._suggestion_block("x ``` y").startswith("````suggestion\n")


DIFF = "--- a/f.tf\n+++ b/f.tf\n@@ -2,2 +2,2 @@\n b\n-c\n+C\n"


def test_diff_applies_to_the_file_it_was_drafted_on():
    assert handler.diff_applies_to(DIFF, "a\nb\nc\nd\n")


def test_diff_does_not_apply_to_a_changed_file():
    assert not handler.diff_applies_to(DIFF, "a\nb\nchanged\nd\n")


def test_diff_applies_to_crlf_content():
    assert handler.diff_applies_to(DIFF, "a\r\nb\r\nc\r\nd\r\n")


# ======================================================================
# report: which fixes may be posted
# ======================================================================

def _fix(fid, diff, applies_after=()):
    return {"finding_id": fid, "file": "f.tf", "rule_id": f"R-{fid}", "status": "fix-proposed",
            "line_range": ["1", "1"],
            "proposed_fix": {"diff": diff, "self_check_passed": True,
                             "applies_after": [{"finding_id": a, "diff_sha256": h} for a, h in applies_after]}}


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def test_chain_tip_is_the_fix_covering_all_others():
    first = _fix("1", "d1")
    second = _fix("2", "d2", [("1", _h("d1"))])
    assert handler.chain_tip({"1": first, "2": second})["finding_id"] == "2"


def test_chain_with_an_edited_link_has_no_tip():
    first = _fix("1", "d1-edited-since")
    second = _fix("2", "d2", [("1", _h("d1"))])
    assert handler.chain_tip({"1": first, "2": second}) is None


def test_fix_outside_the_chain_means_no_tip():
    assert handler.chain_tip({"1": _fix("1", "d1"), "2": _fix("2", "d2")}) is None


HEAD_FILE = "a\nb\nc\nd\n"
CORRECTED = "a\nb\nC\nd\n"


def _plan(fixes, visible):
    contents = {"scans/p/f.tf": HEAD_FILE, "fixes/p/1/f.tf": CORRECTED}
    with patch.object(handler, "_s3_text", side_effect=lambda k: contents[k]):
        return handler.plan_file("p", "f.tf", fixes, visible)


def test_plan_posts_a_verified_fix_inside_the_diff():
    plan = _plan([_fix("1", DIFF)], visible={2, 3, 4})
    assert plan["hunks"] == [{"start": 3, "end": 3, "text": "C"}]
    comment = plan["comments"][0]
    assert comment["line"] == 3 and comment["side"] == "RIGHT" and "start_line" not in comment
    assert "```suggestion\nC\n```" in comment["body"]


def test_plan_holds_a_fix_that_reaches_outside_the_diff():
    plan = _plan([_fix("1", DIFF)], visible={1, 2})
    assert "hunks" not in plan and "outside" in plan["reason"]


def test_plan_holds_a_fix_drafted_on_an_earlier_commit():
    stale = DIFF.replace(" b\n-c", " b\n-something-else")
    plan = _plan([_fix("1", stale)], visible={1, 2, 3, 4})
    assert "earlier commit" in plan["reason"]


def test_plan_ignores_fixes_that_failed_their_self_check():
    fix = _fix("1", DIFF)
    fix["proposed_fix"]["self_check_passed"] = False
    assert _plan([fix], visible={3}) is None


def test_plan_never_posts_model_prose():
    fix = _fix("1", DIFF)
    fix["proposed_fix"]["rationale"] = "MODEL PROSE"
    fix["proposed_fix"]["assumptions"] = ["MODEL ASSUMPTION"]
    body = _plan([fix], visible={3})["comments"][0]["body"]
    assert "MODEL" not in body


# ======================================================================
# report: the check run and the review
# ======================================================================

def _finding(fid, line, status="mapped", severity="HIGH", file="f.tf"):
    return {"finding_id": fid, "file": file, "line_range": [str(line), str(line)], "status": status,
            "severity": severity, "rule_id": f"R{fid}", "source": "trivy", "title": f"T{fid}",
            "control_mappings": [{"control_id": "CIS 1.1"}]}


def _report(findings, remediate=False, fetch_status="ok", patch_text="@@ -1,2 +1,3 @@\n a\n+b\n c"):
    state = {"pr_id": "p", "github": {**GITHUB, "trigger": "fixes" if remediate else "push"},
             "remediate": remediate, "scan": {"scan_errors": []},
             "fetch": {"status": fetch_status, "check_run_id": 55, "kept_count": 3,
                       "changed_files": ["f.tf"], "reason": "why not"}}
    files_json = json.dumps([{"filename": "f.tf", "status": "modified", "patch": patch_text}]).encode()
    with patch.object(handler, "installation_token", return_value="tok"), \
            patch.object(handler, "_request", return_value={}) as request, \
            patch.object(handler, "query_findings", return_value=findings), \
            patch.object(handler, "post_suggestions", return_value=([], [])) as suggest, \
            patch.object(handler, "s3") as s3:
        s3.get_object.return_value = {"Body": io.BytesIO(files_json)}
        result = handler.handler({"action": "report", "execution_name": "exec-1", "state": state}, None)
    return result, request, suggest


def test_report_annotates_only_findings_on_added_lines():
    _, request, _ = _report([_finding("1", 2), _finding("2", 1), _finding("3", 2, file="other.tf")])
    body = request.call_args.args[3]
    assert body["status"] == "completed" and body["conclusion"] == "neutral"
    assert [a["title"] for a in body["output"]["annotations"]] == ["R1 (high)"]
    assert body["output"]["annotations"][0]["annotation_level"] == "failure"


def test_report_ignores_superseded_and_no_longer_detected():
    gone = _finding("2", 2)
    gone["no_longer_detected"] = "t"
    _, request, _ = _report([_finding("1", 2, status="superseded"), gone])
    assert "annotations" not in request.call_args.args[3]["output"]


def test_report_sends_annotations_in_batches_of_fifty():
    findings = [_finding(str(i), 2) for i in range(120)]
    _, request, _ = _report(findings)
    calls = [c.args[3] for c in request.call_args_list]
    assert [len(c["output"].get("annotations", [])) for c in calls] == [50, 50, 20]
    assert "status" not in calls[0] and calls[-1]["status"] == "completed"


def test_report_offers_draft_fixes_when_changed_files_have_mapped_findings():
    _, request, suggest = _report([_finding("1", 2)])
    assert request.call_args.args[3]["actions"][0]["identifier"] == "draft_fixes"
    suggest.assert_not_called()


def test_report_does_not_offer_draft_fixes_without_mapped_findings():
    _, request, _ = _report([_finding("1", 2, status="raw")])
    assert "actions" not in request.call_args.args[3]


def test_fixes_run_posts_suggestions_and_offers_no_button():
    _, request, suggest = _report([_finding("1", 2)], remediate=True)
    suggest.assert_called_once()
    assert "actions" not in request.call_args.args[3]


def test_unusable_snapshot_completes_the_run_without_scanning():
    result, request, _ = _report([], fetch_status="too_large")
    body = request.call_args.args[3]
    assert result == {"status": "too_large"}
    assert body["conclusion"] == "neutral" and body["output"]["summary"] == "why not"


def test_suggestions_are_not_posted_twice_for_one_execution():
    with patch.object(handler, "_paginate",
                      return_value=[{"body": "<!-- cascadesec:exec-1 -->\n..."}]), \
            patch.object(handler, "_request") as request:
        assert handler.post_suggestions(GITHUB, "p", "exec-1", [], {"f.tf": {1}}, "tok") == ([], [])
    request.assert_not_called()


def test_rejected_review_is_reported_not_raised():
    plan = {"file": "f.tf", "hunks": [{}], "comments": [{"path": "f.tf"}]}
    with patch.object(handler, "_paginate", return_value=[]), \
            patch.object(handler, "plan_file", return_value=plan), \
            patch.object(handler, "_request", side_effect=handler.GitHubError(422, "line")):
        posted, held = handler.post_suggestions(GITHUB, "p", "exec-1", [{"file": "f.tf"}], {"f.tf": {1}}, "tok")
    assert posted == [] and held[0]["reason"] == "GitHub rejected the suggestion"


# ======================================================================
# the failure backstop
# ======================================================================

def _failed(input_obj, status="FAILED"):
    return {"detail-type": "Step Functions Execution Status Change",
            "detail": {"name": "exec-1", "status": status, "input": json.dumps(input_obj)}}


def test_failed_execution_completes_its_own_check_run():
    runs = {"check_runs": [
        {"id": 1, "external_id": "exec-1", "status": "in_progress"},
        {"id": 2, "external_id": "some-other-exec", "status": "in_progress"},
    ]}
    with patch.object(handler, "installation_token", return_value="tok"), \
            patch.object(handler, "_request", side_effect=[runs, {}]) as request:
        handler.handler(_failed({"github": GITHUB}), None)

    method, path, _, body = request.call_args_list[1].args
    assert (method, path) == ("PATCH", "/repos/o/r/check-runs/1")
    assert body["conclusion"] == "neutral"
    assert len(request.call_args_list) == 2


def test_failure_before_fetch_still_shows_on_the_pr():
    with patch.object(handler, "installation_token", return_value="tok"), \
            patch.object(handler, "_request", side_effect=[{"check_runs": []}, {}]) as request:
        handler.handler(_failed({"github": GITHUB}, status="TIMED_OUT"), None)

    method, path, _, body = request.call_args_list[1].args
    assert (method, path) == ("POST", "/repos/o/r/check-runs")
    assert body["status"] == "completed" and body["external_id"] == "exec-1"


def test_manual_run_failure_is_not_githubs_business():
    with patch.object(handler, "installation_token") as token:
        assert handler.handler(_failed({"pr_id": "manual-1"}), None) == {"skipped": "not a GitHub execution"}
    token.assert_not_called()


def test_unknown_action_is_an_error():
    with pytest.raises(ValueError):
        handler.handler({"action": "nope"}, None)
