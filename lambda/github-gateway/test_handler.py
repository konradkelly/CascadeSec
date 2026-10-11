"""Tests for github-gateway's handler. KMS, S3, DynamoDB and GitHub are all
mocked -- no AWS or network calls."""

import base64
import difflib
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
                      "changed_files": ["main.tf"], "reason": None,
                      "cdk_runs": [], "cdk_skipped": [], "changed_prefixes": [],
                      "allow_empty_scan": False}
    stored = [c for c in s3.put_object.call_args_list if c.kwargs["Key"].startswith("github/")]
    assert stored[0].kwargs["Key"] == f"github/gh-123456-7/{HEAD}/files.json"


# ---------- fetch: CDK apps (docs/sandbox-spec.md §9 step 2) ----------

CDK_APP = [
    ("o-r-sha/infra/cdk.json", b'{"app": "npx tsx bin/app.ts"}'),
    ("o-r-sha/infra/package.json", b"{}"),
    ("o-r-sha/infra/package-lock.json", b"{}"),
    ("o-r-sha/infra/bin/app.ts", b"new App()"),
    ("o-r-sha/infra/node_modules/x/index.js", b"x"),
    ("o-r-sha/infra/cdk.out/Old.template.json", b'{"Resources": {}}'),
    ("o-r-sha/README.md", b"readme"),
]


@pytest.fixture(autouse=True)
def cdk_synthesis_enabled(monkeypatch):
    monkeypatch.setattr(handler, "CDK_SYNTHESIS_ENABLED", True)


def test_with_synthesis_off_an_app_is_reported_not_run(monkeypatch):
    monkeypatch.setattr(handler, "CDK_SYNTHESIS_ENABLED", False)
    result, puts = _fetch_with(CDK_APP + [("o-r-sha/main.tf", b"x")])
    assert result["cdk_runs"] == [] and result["cdk_skipped"][0]["status"] == "disabled"
    assert not any(k.startswith("projects/") for k in puts)


def _fetch_with(members, github=None, pr_files=()):
    """fetch over a real tarball, through read_snapshot."""
    def download(_github, _token, project=None):
        return handler.read_snapshot(_tarball(members), project)
    with patch.object(handler, "installation_token", return_value="tok"),             patch.object(handler, "_request", return_value={"id": 55}),             patch.object(handler, "_paginate", return_value=list(pr_files)),             patch.object(handler, "s3") as s3,             patch.object(handler, "download_snapshot", side_effect=download):
        s3.get_paginator.return_value.paginate.return_value = [{}]
        event = _fetch_event()
        event["github"] = {**event["github"], "from_fork": False, **(github or {})}
        result = handler.handler(event, None)
    puts = {c.kwargs["Key"]: c.kwargs["Body"] for c in s3.put_object.call_args_list}
    return result, puts


def _project_names(body):
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        return sorted(tar.getnames())


def test_read_snapshot_hands_every_safe_file_to_the_project():
    project = handler.ProjectArchive()
    kept = handler.read_snapshot(_tarball(CDK_APP + [
        ("o-r-sha/main.tf", b"x"),
        ("o-r-sha/../escape.ts", b"x"),
        ("o-r-sha/link.ts", tarfile.SYMTYPE, "/etc/passwd"),
    ]), project)
    assert kept == {"main.tf": b"x"}
    # node_modules and cdk.out stay out: fetch installs the one, and the
    # other is where the sandbox's own output goes.
    assert sorted(project.files) == ["README.md", "infra/bin/app.ts", "infra/cdk.json",
                                     "infra/package-lock.json", "infra/package.json", "main.tf"]
    assert _project_names(project.finish()) == sorted(project.files)
    project.close()


def test_a_cdk_app_is_kept_for_the_sandbox_and_its_templates_mapped_if_touched():
    result, puts = _fetch_with(CDK_APP + [("o-r-sha/main.tf", b"x")], pr_files=[
        {"filename": "infra/bin/app.ts", "status": "modified", "patch": "@@ -1 +1 @@\n+x"}])
    key = f"projects/gh-123456-7/{HEAD}.tgz"
    assert result["status"] == "ok"
    assert result["cdk_runs"] == [{"app_dir": "infra", "project_key": key}]
    assert result["changed_prefixes"] == ["infra/cdk.out/"]
    assert result["allow_empty_scan"] is False
    assert "infra/bin/app.ts" in _project_names(puts[key])


def test_an_untouched_app_is_synthesized_but_not_mapped():
    result, _ = _fetch_with(CDK_APP + [("o-r-sha/main.tf", b"x")], pr_files=[
        {"filename": "main.tf", "status": "modified", "patch": "@@ -1 +1 @@\n+x"}])
    assert len(result["cdk_runs"]) == 1 and result["changed_prefixes"] == []


def test_a_repository_that_is_only_cdk_scans_what_synth_writes():
    result, _ = _fetch_with(CDK_APP)
    assert result["status"] == "ok" and result["kept_count"] == 0
    assert result["allow_empty_scan"] is True


@pytest.mark.parametrize("github", [{"from_fork": True}, {"from_fork": None}])
def test_a_fork_is_not_run(github):
    result, puts = _fetch_with(CDK_APP + [("o-r-sha/main.tf", b"x")], github=github)
    assert result["cdk_runs"] == []
    assert result["cdk_skipped"][0]["status"] == "needs_approval"
    assert not any(k.startswith("projects/") for k in puts)


def test_an_input_without_the_fork_field_is_treated_as_a_fork():
    project = handler.ProjectArchive()
    project.names = {"cdk.json", "package.json", "package-lock.json"}
    assert handler.cdk_apps(project, {})[0]["status"] == "needs_approval"
    project.close()


@pytest.mark.parametrize("drop,why", [("package.json", "TypeScript and JavaScript"),
                                      ("package-lock.json", "package-lock.json")])
def test_an_app_npm_cannot_install_is_unsupported(drop, why):
    members = [m for m in CDK_APP if not m[0].endswith("/" + drop)] + [("o-r-sha/main.tf", b"x")]
    result, _ = _fetch_with(members)
    [skipped] = result["cdk_skipped"]
    assert skipped["status"] == "unsupported" and why in skipped["reason"]


def test_only_cdk_and_nothing_runnable_is_empty_and_says_why():
    result, _ = _fetch_with(CDK_APP, github={"from_fork": True})
    assert result["status"] == "empty"
    assert "`infra`" in result["reason"] and "fork" in result["reason"]


def test_an_oversized_project_reports_its_apps_and_scans_the_rest(monkeypatch):
    monkeypatch.setattr(handler, "MAX_PROJECT_BYTES", 20)
    result, _ = _fetch_with(CDK_APP + [("o-r-sha/main.tf", b"x")])
    assert result["status"] == "ok" and result["kept_count"] == 1
    assert result["cdk_skipped"][0]["status"] == "too_large"


def test_apps_past_the_cap_are_reported(monkeypatch):
    monkeypatch.setattr(handler, "MAX_CDK_APPS", 1)
    second = [(n.replace("/infra/", "/infra2/"), d) for n, d in CDK_APP if "/infra/" in n]
    result, _ = _fetch_with(CDK_APP + second)
    assert [r["app_dir"] for r in result["cdk_runs"]] == ["infra"]
    assert result["cdk_skipped"] == [{"app_dir": "infra2", "status": "too_many",
                                      "reason": "only the first 1 CDK apps are synthesized"}]


def test_a_root_app_maps_under_the_root_cdk_out():
    members = [(n.replace("/infra/", "/"), d) for n, d in CDK_APP]
    result, _ = _fetch_with(members, pr_files=[{"filename": "bin/app.ts", "status": "modified"}])
    assert result["cdk_runs"][0]["app_dir"] == "."
    assert result["changed_prefixes"] == ["cdk.out/"]


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


def _stale_fix(file, base_text, status="fix-proposed"):
    return {"finding_id": file, "file": file, "status": status,
            "proposed_fix": {"diff": "d", "base_sha256": _h(base_text) if base_text else None}}


def test_select_files_takes_a_changed_file_whose_only_fix_is_stale():
    """cascadesec-testbed #3 without the bastion: the KMS fix was drafted on
    commit A, nothing on the file is mapped, and "run Draft fixes again"
    must still reach it, or it is never redrafted (write-back-spec §8)."""
    findings = [
        _stale_fix("stale.tf", "commit A"),
        _stale_fix("legacy.tf", None, status="resolved"),   # drafted before bases
        _stale_fix("current.tf", "current.tf now"),
        _stale_fix("held.tf", "commit A", status="needs-human-only"),
        {**_stale_fix("done.tf", "commit A", status="resolved"),
         "proposed_fix": {"diff": "d", "base_sha256": _h("commit A"), "committed": {"sha": "c"}}},
    ]
    snapshots = {f"scans/p/{f['file']}": f"{f['file']} now" for f in findings}
    with patch.object(handler, "query_findings", return_value=findings), \
            patch.object(handler, "_s3_text", side_effect=snapshots.__getitem__):
        result = handler.handler({"action": "select_files", "pr_id": "p",
                                  "changed_files": [f["file"] for f in findings], "map": {}}, None)
    assert result["files"] == ["legacy.tf", "stale.tf"]


def test_a_stale_fix_on_a_file_the_pr_deleted_is_not_selected():
    missing = handler.ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
    with patch.object(handler, "_s3_text", side_effect=missing):
        assert handler.stale_files("p", [_stale_fix("gone.tf", "commit A")]) == set()


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


def test_content_hash_agrees_with_remediation_agent():
    # The two helpers compare each other's output, so they must hash alike --
    # CRLF included, which neither may normalise.
    assert handler._content_sha256("a\r\nb\n") == hashlib.sha256(b"a\r\nb\n").hexdigest()


# ======================================================================
# report: which fixes may be posted
# ======================================================================

def _fix(fid, diff, applies_after=()):
    return {"finding_id": fid, "file": "f.tf", "rule_id": f"R-{fid}", "status": "fix-proposed",
            "line_range": ["1", "1"],
            "proposed_fix": {"diff": diff, "self_check_passed": True,
                             # Drafted on the file the plan tests put at the head.
                             "base_sha256": _h(HEAD_FILE),
                             "applies_after": [{"finding_id": a, "diff_sha256": h} for a, h in applies_after]}}


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def test_chain_tip_is_the_fix_covering_all_others():
    first = _fix("1", "d1")
    second = _fix("2", "d2", [("1", _h("d1"))])
    assert handler.chain_tip({"1": first, "2": second})["finding_id"] == "2"


def test_a_fix_built_on_an_edited_link_is_not_the_tip():
    # 2 was drafted on 1 as it was; 1 has changed since, so 2's corrected
    # file no longer follows from anything posted. 1 still stands alone.
    first = _fix("1", "d1-edited-since")
    second = _fix("2", "d2", [("1", _h("d1"))])
    assert handler.chain_tip({"1": first, "2": second})["finding_id"] == "1"


def test_fix_built_on_a_held_fix_is_not_the_tip():
    # cascadesec-testbed #2: KMS rotation (1) then RDS encryption (2), both
    # verified; the SSH fix (4) was drafted on a held fix (3), so its file
    # carries the held change. The tip is 2, not 4.
    fixes = {
        "1": _fix("1", "d1"),
        "2": _fix("2", "d2", [("1", _h("d1"))]),
        "4": _fix("4", "d4", [("1", _h("d1")), ("2", _h("d2")), ("3", _h("d3-held"))]),
    }
    assert handler.chain_tip(fixes)["finding_id"] == "2"


def test_every_fix_built_on_a_held_one_means_no_tip():
    # The ledger Deployment: its first fix was held, and every later one is
    # drafted on it.
    fixes = {"2": _fix("2", "d2", [("1", _h("d1-held"))]),
             "3": _fix("3", "d3", [("1", _h("d1-held")), ("2", _h("d2"))])}
    assert handler.chain_tip(fixes) is None


def test_plan_reports_the_verified_fixes_it_leaves_out():
    root = _fix("1", DIFF)
    on_held = _fix("4", "d4", [("1", _h(DIFF)), ("3", _h("held"))])
    plan = _plan([root, on_held], visible={2, 3, 4})
    assert plan["chain"] == ["1"]
    assert plan["left_out"] == ["R-4"]


def test_summary_says_why_a_verified_fix_was_left_out():
    state = {"pr_id": "p", "github": GITHUB, "fetch": {"kept_count": 1}, "scan": {}}
    posted = [{"file": "f.tf", "hunks": [{}], "left_out": ["CKV_AWS_24"]}]
    summary = handler.build_summary(state=state, findings=[], on_added=[], posted=posted, held=[],
                                    remediate=True, offer_fixes=False, trigger="fixes")
    assert "`CKV_AWS_24` not posted -- drafted on top of a fix held for review" in summary


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
    fix = _fix("1", DIFF)
    fix["proposed_fix"]["base_sha256"] = _h("a\nb\nsomething-else\nd\n")
    plan = _plan([fix], visible={1, 2, 3, 4})
    assert "changed since" in plan["reason"]


KEY_AT_A = ('# Encryption key for the reporting service\'s exports.\n'
            'resource "aws_kms_key" "reports" {\n'
            '  description             = "Reporting service exports"\n'
            '  deletion_window_in_days = 30\n'
            '}\n')
ALIAS = ('\nresource "aws_kms_alias" "reports" {\n'
         '  name          = "alias/reports"\n'
         '  target_key_id = aws_kms_key.reports.key_id\n'
         '}\n')


def test_a_fix_drafted_before_the_file_changed_is_not_posted_over_it():
    """cascadesec-testbed #3 (docs/write-back-spec.md §8). Rotation was
    drafted on commit A; commit B appended an alias below the key. The
    finding kept its id and its fix, the fix's diff still applied to B, and
    the corrected file -- written before the alias existed -- was posted over
    B as "part 2 of 2": an empty suggestion deleting the alias."""
    rotated = KEY_AT_A.replace("= 30\n", "= 30\n  enable_key_rotation     = true\n")
    diff = "".join(difflib.unified_diff(KEY_AT_A.splitlines(True), rotated.splitlines(True),
                                        "a/reports.tf", "b/reports.tf"))
    fix = {**_fix("kms", diff), "file": "reports.tf", "rule_id": "CKV_AWS_7"}
    fix["proposed_fix"]["base_sha256"] = _h(KEY_AT_A)
    at_b = KEY_AT_A + ALIAS
    contents = {"scans/p/reports.tf": at_b, "fixes/p/kms/reports.tf": rotated}
    with patch.object(handler, "_s3_text", side_effect=lambda k: contents[k]):
        plan = handler.plan_file("p", "reports.tf", [fix], visible_lines=set(range(1, 11)))
    assert "hunks" not in plan
    assert "changed since" in plan["reason"]


def test_a_fix_with_no_recorded_base_is_not_posted():
    fix = _fix("1", DIFF)
    del fix["proposed_fix"]["base_sha256"]
    plan = _plan([fix], visible={1, 2, 3, 4})
    assert "hunks" not in plan and "Draft fixes again" in plan["reason"]


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


def _report(findings, remediate=False, fetch_status="ok", patch_text="@@ -1,2 +1,3 @@\n a\n+b\n c",
            extra_state=None, pr_path="f.tf"):
    state = {"pr_id": "p", "github": {**GITHUB, "trigger": "fixes" if remediate else "push"},
             "remediate": remediate, "scan": {"scan_errors": []},
             "fetch": {"status": fetch_status, "check_run_id": 55, "kept_count": 3,
                       "changed_files": ["f.tf"], "reason": "why not"},
             **(extra_state or {})}
    files_json = json.dumps([{"filename": pr_path, "status": "modified", "patch": patch_text}]).encode()
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


def test_report_ignores_findings_the_scan_no_longer_reports():
    gone = _finding("2", 2)
    gone["no_longer_detected"] = "t"
    _, request, _ = _report([gone])
    assert "annotations" not in request.call_args.args[3]["output"]


@pytest.mark.parametrize("status", ["superseded", "needs-human-only", "fix-proposed", "resolved"])
def test_report_annotates_a_finding_whatever_became_of_its_fix(status):
    # A fix is not applied until someone commits it; the line is still wrong.
    # Leaving superseded out dropped 6 of 18 annotations on PugetScope #10.
    _, request, _ = _report([_finding("1", 2, status=status)])
    assert len(request.call_args.args[3]["output"]["annotations"]) == 1


def test_report_sends_annotations_in_batches_of_fifty():
    findings = [_finding(str(i), 2) for i in range(120)]
    _, request, _ = _report(findings)
    calls = [c.args[3] for c in request.call_args_list]
    assert [len(c["output"].get("annotations", [])) for c in calls] == [50, 50, 20]
    assert "status" not in calls[0] and calls[-1]["status"] == "completed"


def _cdk_finding(fid, origin, template_line=180):
    f = _finding(fid, template_line, file="infra/cdk.out/ProbeStack.template.json")
    f.update(target_type="cdk", resource="/ProbeStack/Net/Ssh/Resource", origin=origin)
    return f


def test_a_cdk_finding_is_annotated_on_the_source_line_that_made_it():
    finding = _cdk_finding("1", {"file": "infra/lib/network.ts", "line": 2, "logical_id": "NetSsh9740AB70"})
    _, request, _ = _report([finding], pr_path="infra/lib/network.ts")
    [ann] = request.call_args.args[3]["output"]["annotations"]
    assert (ann["path"], ann["start_line"], ann["end_line"]) == ("infra/lib/network.ts", 2, 2)
    assert "infra/cdk.out/ProbeStack.template.json" in ann["message"]
    assert "synthesizing the app again" in ann["message"]


@pytest.mark.parametrize("origin", [
    {"file": "infra/lib/network.ts", "line": 1},   # a line the PR did not add
    {"file": "other.ts", "line": 2},               # a file the PR did not touch
    {"file": None, "line": None},                  # a resource with no source line
    None,
    {"file": "infra/lib/network.ts", "line": "x"},
])
def test_a_cdk_finding_off_the_added_lines_is_not_annotated(origin):
    _, request, _ = _report([_cdk_finding("1", origin)], pr_path="infra/lib/network.ts")
    assert "annotations" not in request.call_args.args[3]["output"]


def test_a_cdk_finding_is_never_placed_on_the_template_itself():
    # Even if the PR somehow added the template's own line.
    _, request, _ = _report([_cdk_finding("1", None, template_line=2)],
                            pr_path="infra/cdk.out/ProbeStack.template.json")
    assert "annotations" not in request.call_args.args[3]["output"]


def test_a_cdk_finding_on_a_source_file_the_pr_changed_offers_draft_fixes():
    # sandbox-spec §9 step 3: its fix is drafted in the source file, which is
    # what the PR changed -- not the template, which it never could.
    finding = _cdk_finding("1", {"file": "f.tf", "line": 2})
    _, request, _ = _report([finding])
    assert request.call_args.args[3]["actions"][0]["identifier"] == "draft_fixes"


def test_a_cdk_finding_whose_source_the_pr_did_not_change_offers_nothing():
    finding = _cdk_finding("1", {"file": "infra/lib/untouched.ts", "line": 2})
    _, request, _ = _report([finding])
    assert "actions" not in request.call_args.args[3]


def test_select_files_takes_the_source_file_of_a_cdk_finding():
    finding = {**_cdk_finding("1", {"file": "infra/lib/storage.ts", "line": 6}), "status": "mapped"}
    with patch.object(handler, "query_findings", return_value=[finding]):
        out = handler.handler({"action": "select_files", "pr_id": "p",
                               "changed_files": ["infra/lib/storage.ts"], "map": {}}, None)
    assert out["files"] == ["infra/lib/storage.ts"]


def test_the_summary_accounts_for_every_cdk_app():
    synth = [
        {"app_dir": "infra", "status": "ok", "templates": ["infra/cdk.out/ProbeStack.template.json",
                                                         "infra/cdk.out/assembly-Prod/ProdApi.template.json"]},
        {"app_dir": "svc", "status": "failed", "reason": "the app exited 1"},
        {"app_dir": "evil", "status": "error", "reason": "x` [click](https://evil.example) @org/team\nmore"},
    ]
    skipped = [{"app_dir": "fork-app", "status": "needs_approval", "reason": "this pull request comes from a fork"}]
    _, request, _ = _report([], extra_state={"synth": synth, "fetch": {
        "status": "ok", "check_run_id": 55, "kept_count": 0, "changed_files": [], "cdk_skipped": skipped}})
    summary = request.call_args.args[3]["output"]["summary"]
    assert "- `infra`: 2 stack(s) synthesized: `ProbeStack`, `ProdApi`" in summary
    assert "- `svc`: not synthesized, the app failed: `the app exited 1`" in summary
    assert "- `fork-app`: not synthesized, this pull request comes from a fork" in summary
    # What the sandbox reports is code: no link, no mention, no way out of the span.
    evil = next(line for line in summary.split("\n") if line.startswith("- `evil`"))
    assert evil.endswith("`x [click](https://evil.example) @org/team more`")
    assert evil.count("`") == 4


def test_no_cdk_section_without_cdk():
    _, request, _ = _report([_finding("1", 2)])
    assert "CDK" not in request.call_args.args[3]["output"]["summary"]


def test_report_offers_draft_fixes_when_changed_files_have_mapped_findings():
    _, request, suggest = _report([_finding("1", 2)])
    assert request.call_args.args[3]["actions"][0]["identifier"] == "draft_fixes"
    suggest.assert_not_called()


def test_report_does_not_offer_draft_fixes_without_mapped_findings():
    _, request, _ = _report([_finding("1", 2, status="raw")])
    assert "actions" not in request.call_args.args[3]


def test_report_offers_draft_fixes_for_a_stale_fix():
    stale = {**_finding("1", 2, status="fix-proposed"),
             "proposed_fix": {"diff": "d", "base_sha256": _h("the file at an earlier commit")}}
    with patch.object(handler, "_s3_text", return_value="the file now"):
        _, request, _ = _report([stale])
    body = request.call_args.args[3]
    assert body["actions"][0]["identifier"] == "draft_fixes"
    assert "redrafts any fix whose file has changed" in body["output"]["summary"]


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


@pytest.mark.parametrize("line_range", [[None, None], [], None, ["x", "y"]])
def test_a_finding_without_lines_is_counted_not_annotated(line_range):
    # Trivy's KSV-0117 came back as [None, None] on the first PugetScope run,
    # and report died on it.
    lineless = _finding("9", 2)
    lineless["line_range"] = line_range
    result, request, _ = _report([_finding("1", 2), lineless])

    body = request.call_args.args[3]
    assert [a["title"] for a in body["output"]["annotations"]] == ["R1 (high)"]
    assert "of **2** in the repository" in body["output"]["summary"]
    assert result["annotations"] == 1


def test_annotation_title_leaves_out_a_severity_the_scanner_did_not_give():
    assert handler.annotation(_finding("1", 2, severity="UNKNOWN"))["title"] == "R1"
    assert handler.annotation(_finding("1", 2, severity="HIGH"))["title"] == "R1 (high)"


# ======================================================================
# the offer (github-first-review-spec §3.1)
# ======================================================================

def _offer(fixes, contents=None):
    contents = contents or {"scans/p/f.tf": HEAD_FILE, "fixes/p/1/f.tf": CORRECTED,
                            "fixes/p/2/f.tf": "A\nb\nC\nd\n"}

    def read(key):
        if key not in contents:
            raise handler.ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return contents[key]

    with patch.object(handler, "_s3_text", side_effect=read):
        return handler.plan_offer("p", fixes)


def test_the_offer_includes_a_fix_outside_the_prs_diff():
    # A suggestion needs its lines in the diff; the offer does not, which is
    # the point of it (testbed #2's fixes were mostly outside).
    [o] = _offer([_fix("1", DIFF)])
    assert (o["file"], o["tip"], o["chain"], o["rules"]) == ("f.tf", "1", ["1"], ["R-1"])
    assert o["content_sha256"] == _h(CORRECTED)
    assert "-c\n+C\n" in o["diff"]


def test_the_offer_is_the_longest_verified_chain():
    first, second = _fix("1", DIFF), _fix("2", "d2", [("1", _h(DIFF))])
    [o] = _offer([first, second])
    assert (o["tip"], o["chain"]) == ("2", ["1", "2"])


def test_an_approved_fix_is_offered_and_a_committed_one_is_not():
    approved = {**_fix("1", DIFF), "status": "resolved"}
    assert _offer([approved])[0]["tip"] == "1"
    committed = _fix("1", DIFF)
    committed["proposed_fix"]["committed"] = {"sha": "c"}
    assert _offer([committed]) == []


@pytest.mark.parametrize("change", [
    lambda f: f["proposed_fix"].update(base_sha256=_h("an earlier version")),
    lambda f: f["proposed_fix"].pop("base_sha256"),
    lambda f: f["proposed_fix"].update(self_check_passed=False),
    lambda f: f.update(status="needs-human-only"),
    lambda f: f.update(no_longer_detected="t"),
], ids=["stale-base", "no-base", "unverified", "held", "gone"])
def test_only_a_verified_fix_on_the_current_head_is_offered(change):
    fix = _fix("1", DIFF)
    change(fix)
    assert _offer([fix]) == []


def test_a_fix_whose_file_is_gone_is_not_offered():
    assert _offer([_fix("1", DIFF)], contents={"fixes/p/1/f.tf": CORRECTED}) == []


def test_the_offer_section_shows_each_change_and_escapes_the_path():
    offer = [{"file": "<b>x.tf", "rules": ["CKV_AWS_7"], "diff": "--- a\n+++ b\n+rotation\n"}]
    text = "\n".join(handler.offer_section(offer))
    assert "<code>&lt;b&gt;x.tf</code>: `CKV_AWS_7`" in text
    assert "```diff\n--- a\n+++ b\n+rotation\n```" in text
    assert "Approve them in the dashboard" in text


def test_an_offer_too_large_to_show_still_lists_its_files():
    big = [{"file": f"f{i}.tf", "rules": ["R"], "diff": "+x\n" * 9000} for i in range(3)]
    text = "\n".join(handler.offer_section(big))
    assert "`f2.tf`: `R` (the change is too large to show here" in text
    assert len(text) < 65000


def test_a_fixes_run_reports_the_offer_for_the_state_machine_to_store():
    offered = [{"file": "f.tf", "tip": "1", "chain": ["1"], "rules": ["R1"],
                "content_sha256": "h", "diff": "+x\n"}]
    with patch.object(handler, "plan_offer", return_value=offered) as plan:
        result, request, _ = _report([_finding("1", 2)], remediate=True)
    assert result["offer"] == {"check_run_id": 55, "head_sha": HEAD,
                               "files": [{"file": "f.tf", "tip": "1", "chain": ["1"],
                                          "content_sha256": "h"}]}
    assert "Ready to commit" in request.call_args.args[3]["output"]["summary"]
    # Only the changed files' findings are considered.
    assert [f["file"] for f in plan.call_args.args[1]] == ["f.tf"]


def test_a_push_run_makes_no_offer():
    with patch.object(handler, "plan_offer") as plan:
        result, _, _ = _report([_finding("1", 2)])
    plan.assert_not_called()
    assert "offer" not in result


# ======================================================================
# report_commit (github-first-review-spec §3.6)
# ======================================================================

def _report_commit(outcome):
    event = {"action": "report_commit", "pr_id": "p", "check_run_id": 55,
             "sender": {"login": "konradkelly", "id": 4242}, "github": GITHUB, "commit": outcome}
    with patch.object(handler, "installation_token", return_value="tok") as token, \
            patch.object(handler, "_request", return_value={}) as request:
        result = handler.handler(event, None)
    method, path, _, body = request.call_args.args
    assert (method, path) == ("POST", "/repos/o/r/check-runs")
    # Checks write only: reporting needs nothing else.
    assert token.call_args.args[1] == {"checks": "write", "metadata": "read"}
    return result, body


def test_a_committed_click_is_reported_on_the_new_commit():
    result, body = _report_commit({
        "status": "committed", "commit_sha": "c" * 40, "requested_by": "github:konradkelly",
        "files": [{"file": "main.tf", "outcome": "committed", "reason": None}]})
    assert result == {"reported": "committed"}
    assert body["name"] == "CascadeSec fixes" and body["name"] != handler.CHECK_NAME
    assert body["head_sha"] == "c" * 40 and body["conclusion"] == "success"
    summary = body["output"]["summary"]
    assert "Committed in `ccccccc`" in summary and "after konradkelly clicked" in summary
    assert "@konradkelly" not in summary
    assert "| `main.tf` | committed |" in summary


def test_a_held_click_is_reported_on_the_offers_commit_with_the_reason():
    _, body = _report_commit({"status": "held", "requested_by": "github:someone",
                              "reason": "someone has read access; committing needs write access or above"})
    assert body["head_sha"] == HEAD and body["conclusion"] == "neutral"
    assert "needs write access or above" in body["output"]["summary"]


def test_a_failed_click_is_reported_as_not_finished():
    _, body = _report_commit({"status": "failed", "reason": "the committer failed (GitHub 502)"})
    assert body["output"]["title"] == "Commit fixes did not finish"


def test_a_path_or_reason_cannot_break_the_outcome_table():
    _, body = _report_commit({"status": "held", "files": [
        {"file": "a|b.tf", "outcome": "held", "reason": "line one\nline two"}]})
    assert "| `a\\|b.tf` | held: line one line two |" in body["output"]["summary"]


# ---------- the Commit fixes button (github-first-review-spec §3) ----------

OFFERED = [{"file": "f.tf", "tip": "1", "chain": ["1"], "rules": ["R1"],
            "content_sha256": "h", "diff": "+x\n"}]


@pytest.mark.parametrize("enabled, offer, button", [
    (True, OFFERED, True),
    (False, OFFERED, False),   # write-back not deployed: nothing to click to
    (True, [], False),         # nothing verified to commit
])
def test_commit_fixes_is_offered_with_an_offer_once_write_back_is_deployed(enabled, offer, button):
    with patch.object(handler, "COMMIT_FIXES_ENABLED", enabled), \
            patch.object(handler, "plan_offer", return_value=offer):
        _, request, _ = _report([_finding("1", 2)], remediate=True)
    body = request.call_args.args[3]
    actions = [a["identifier"] for a in body.get("actions", [])]
    assert actions == (["commit_fixes"] if button else [])
    summary = body["output"]["summary"]
    if button:
        assert "**Commit fixes** (above) commits" in summary
        assert all(len(a["label"]) <= 20 and len(a["description"]) <= 40 for a in body["actions"])
    elif offer:
        assert "Approve them in the dashboard" in summary


def test_a_push_run_offers_draft_fixes_and_never_commit_fixes():
    with patch.object(handler, "COMMIT_FIXES_ENABLED", True):
        _, request, _ = _report([_finding("1", 2)])
    assert [a["identifier"] for a in request.call_args.args[3]["actions"]] == ["draft_fixes"]


def test_a_runnable_apps_source_joins_the_snapshot():
    # sandbox-spec §9 step 3: a CDK fix edits this file, and remediation,
    # suggestions and the committer read its head content from scans/.
    members = CDK_APP + [("o-r-sha/infra/lib/types.d.ts", b"x"), ("o-r-sha/main.tf", b"x")]
    result, puts = _fetch_with(members, pr_files=[
        {"filename": "infra/bin/app.ts", "status": "modified", "patch": "@@ -1 +1 @@\n+x"}])
    snapshot = sorted(k[len("scans/gh-123456-7/"):] for k in puts if k.startswith("scans/"))
    assert snapshot == ["infra/bin/app.ts", "main.tf"]
    assert result["kept_count"] == 1  # IaC files, as the summary says
    assert result["changed_files"] == ["infra/bin/app.ts"]


def test_a_skipped_apps_source_stays_out():
    result, puts = _fetch_with(CDK_APP + [("o-r-sha/main.tf", b"x")], github={"from_fork": True})
    assert not any(k.startswith("scans/") and k.endswith(".ts") for k in puts)
