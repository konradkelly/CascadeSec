"""Tests for github-committer's handler. KMS, S3, DynamoDB and GitHub are all
mocked -- no AWS or network calls."""

import base64
import copy
import hashlib
import json
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

import handler


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


HEAD = "a\nb\nc\nd\n"
FIXED = {"1": "a\nb\nC\nd\n", "2": "a\nB\nC\nd\n", "3": "A\nB\nC\nd\n"}


def _fix(fid, diff=None, applies_after=(), base=HEAD, verified=True, file="f.tf", **extra):
    return {"finding_id": fid, "file": file, "rule_id": f"R-{fid}", "status": "resolved",
            "proposed_fix": {"diff": diff or f"diff-{fid}", "self_check_passed": verified,
                             "base_sha256": _h(base) if base else None,
                             "applies_after": [{"finding_id": a, "diff_sha256": _h(f"diff-{a}")}
                                               for a in applies_after],
                             **extra}}


def _plan(findings, actions=None, head=HEAD, fixes=None):
    actions = {f["finding_id"]: "approved" for f in findings} if actions is None else actions
    fixes = {f"fixes/p/{i}/f.tf": text for i, text in FIXED.items()} if fixes is None else fixes
    read_head = (lambda path: (head, None)) if isinstance(head, str) else head
    return handler.plan_commit("p", findings, actions, fixes.get, read_head)


# ======================================================================
# plan_commit: which fixes, and which file content
# ======================================================================

def test_an_approved_fix_on_an_unchanged_file_is_committed_whole():
    [plan] = _plan([_fix("1")])
    assert plan["outcome"] == "commit" and plan["reason"] is None
    assert plan["content"] == FIXED["1"] and plan["content_sha256"] == _h(FIXED["1"])
    # The diff the reviewer confirms is head to tip, the change the commit makes.
    assert "-c\n+C\n" in plan["diff"] and plan["diff"].startswith("--- a/f.tf\n+++ b/f.tf\n")
    assert plan["chain"] == [{"finding_id": "1", "rule_id": "R-1", "verified": True, "edited": False}]


@pytest.mark.parametrize("latest", ["rejected", "reopened", None])
def test_only_a_fix_whose_latest_decision_accepts_it_is_planned(latest):
    # The event log, not status: approve then reject leaves status
    # "resolved" while the decision standing on it is a rejection.
    assert _plan([_fix("1")], actions={"1": latest} if latest else {}) == []


def test_a_committed_fix_or_one_no_longer_detected_is_not_planned_again():
    committed = _fix("1", committed={"sha": "c" * 40, "request_id": "r", "at": "t"})
    gone = {**_fix("2"), "no_longer_detected": "t"}
    assert _plan([committed, gone]) == []


def test_the_tip_is_the_longest_approved_chain():
    [plan] = _plan([_fix("1"), _fix("2", applies_after=["1"]), _fix("3", applies_after=["1", "2"])])
    assert plan["tip"] == "3" and [c["finding_id"] for c in plan["chain"]] == ["1", "2", "3"]
    assert plan["content"] == FIXED["3"] and plan["left_out"] == []


def test_a_fix_drafted_on_an_unapproved_one_is_left_out():
    # 2 was drafted on 1's content; 1 is not approved, so 2's file carries
    # a change nobody said yes to. 3 stands alone and is committed.
    findings = [_fix("1"), _fix("2", applies_after=["1"]), _fix("3")]
    [plan] = _plan(findings, actions={"2": "approved", "3": "approved"})
    assert plan["tip"] == "3" and plan["left_out"] == ["R-2"]


def test_a_fix_drafted_on_a_link_edited_since_is_left_out():
    # 1 was edited after 2 was drafted on it: its diff is no longer the one
    # 2's chain recorded.
    findings = [_fix("1", diff="diff-1-edited"), _fix("2", applies_after=["1"])]
    [plan] = _plan(findings)
    assert plan["tip"] == "1" and plan["left_out"] == ["R-2"]


def test_a_chain_from_before_links_carried_hashes_fails_closed():
    legacy = _fix("2")
    legacy["proposed_fix"]["applies_after"] = ["1"]
    [plan] = _plan([_fix("1"), legacy], actions={"2": "approved"})
    assert plan["outcome"] == "held" and plan["left_out"] == ["R-2"]


def test_an_edited_or_unverified_link_is_committed_and_labelled():
    # write-back-spec §5.5 (W4): a person approved it; the push scan is the
    # check it did not get. Labelled so nobody mistakes it for verified.
    findings = [_fix("1", verified=False), _fix("2", applies_after=["1"], verified=False)]
    [plan] = _plan(findings, actions={"1": "approved", "2": "edited"})
    assert plan["outcome"] == "commit"
    assert [(c["verified"], c["edited"]) for c in plan["chain"]] == [(False, False), (False, True)]


# ======================================================================
# plan_commit: the base check
# ======================================================================

KEY_AT_A = 'resource "aws_kms_key" "reports" {\n  description = "exports"\n}\n'
ALIAS = '\nresource "aws_kms_alias" "reports" {\n  name = "alias/reports"\n}\n'
ROTATED_AT_A = KEY_AT_A.replace("}\n", "  enable_key_rotation = true\n}\n")


def test_a_fix_drafted_before_the_file_changed_is_held_not_committed_over_it():
    """cascadesec-testbed #3 (write-back-spec §8). Rotation was drafted on
    commit A; commit B appended an alias. Committing A's corrected file over
    B deletes the alias, and it did once, as a posted suggestion."""
    fix = {**_fix("kms", base=KEY_AT_A), "file": "reports.tf"}
    [plan] = handler.plan_commit("p", [fix], {"kms": "approved"},
                                 {"fixes/p/kms/reports.tf": ROTATED_AT_A}.get,
                                 lambda path: (KEY_AT_A + ALIAS, None))
    assert plan["outcome"] == "held" and "changed since" in plan["reason"]
    assert plan["content"] is None and plan["diff"] is None


def test_a_fix_with_no_recorded_base_is_held():
    [plan] = _plan([_fix("1", base=None)])
    assert plan["outcome"] == "held" and "Draft fixes again" in plan["reason"]


def test_a_head_that_already_has_the_fix_is_already_committed():
    # A retried request, or a person who applied the suggestions: nothing
    # to write, and the base no longer matches because the fix is in it.
    [plan] = _plan([_fix("1")], head=FIXED["1"])
    assert plan["outcome"] == "already" and plan["content"] is None


def test_a_head_that_cannot_be_read_is_held_with_its_reason():
    [plan] = _plan([_fix("1")], head=lambda path: (None, "a symlink at the PR head"))
    assert plan["outcome"] == "held" and plan["reason"] == "a symlink at the PR head"


def test_a_missing_corrected_file_is_held():
    [plan] = _plan([_fix("1")], fixes={})
    assert plan["outcome"] == "held" and "missing" in plan["reason"]


def test_files_are_planned_independently_and_in_order():
    findings = [_fix("1", file="z.tf"), _fix("2", file="a.tf", base=None)]
    fixes = {"fixes/p/1/z.tf": FIXED["1"], "fixes/p/2/a.tf": FIXED["2"]}
    plans = _plan(findings, fixes=fixes)
    assert [(p["file"], p["outcome"]) for p in plans] == [("a.tf", "held"), ("z.tf", "commit")]


# ======================================================================
# commit: against a fake GitHub and an in-memory table
# ======================================================================

class FakeGitHub:
    """Just enough of GitHub's REST and Git Data APIs, with real objects: a
    commit is its tree and parents, a tree is its entries, and the ref
    update is a compare-and-swap, as GitHub's is with force false."""

    def __init__(self, files, *, installed=True, pr=None):
        self.objects, self.flat = {}, {}
        self.installed = installed
        self.writes = []
        root = self._tree_from(files)
        self.head = self._put_commit("initial", root, [])
        self.branch = self.head
        self.pr = pr or {
            "state": "open",
            "head": {"ref": "feature", "sha": self.head, "repo": {"id": 123}},
            "base": {"repo": {"id": 123, "default_branch": "main"}},
        }
        self.before_patch = None

    # ---- objects ----

    def _sha(self, kind, payload):
        return hashlib.sha1(f"{kind}:{json.dumps(payload, sort_keys=True)}".encode()).hexdigest()

    def _put_blob(self, data):
        sha = self._sha("blob", base64.b64encode(data).decode())
        self.objects[sha] = ("blob", data)
        return sha

    def _tree_from(self, files):
        """files: {path: text | (text, mode) | ("symlink", target) | ("submodule",)}"""
        flat = {}
        for path, spec in files.items():
            if isinstance(spec, str):
                spec = (spec, "100644")
            if spec[0] == "symlink":
                flat[path] = {"mode": "120000", "type": "blob", "sha": self._put_blob(spec[1].encode())}
            elif spec[0] == "submodule":
                flat[path] = {"mode": "160000", "type": "commit", "sha": "d" * 40}
            else:
                flat[path] = {"mode": spec[1], "type": "blob", "sha": self._put_blob(spec[0].encode())}
        return self._build(flat)

    def _build(self, flat):
        def build(prefix):
            entries = {}
            for path, entry in flat.items():
                if not path.startswith(prefix):
                    continue
                name, _, rest = path[len(prefix):].partition("/")
                if rest:
                    entries[name] = {"path": name, "mode": "040000", "type": "tree",
                                     "sha": build(prefix + name + "/")}
                else:
                    entries[name] = {"path": name, **entry}
            listing = sorted(entries.values(), key=lambda e: e["path"])
            sha = self._sha("tree", listing)
            self.objects[sha] = ("tree", listing)
            return sha
        root = build("")
        self.flat[root] = dict(flat)
        return root

    def _put_commit(self, message, tree, parents):
        sha = self._sha("commit", [message, tree, parents])
        self.objects[sha] = ("commit", {"message": message, "tree": {"sha": tree}, "parents": parents})
        return sha

    def push(self, files_changed):
        """Someone else pushes to the branch."""
        flat = dict(self.flat[self.objects[self.branch][1]["tree"]["sha"]])
        for path, text in files_changed.items():
            flat[path] = {"mode": "100644", "type": "blob", "sha": self._put_blob(text.encode())}
        self.branch = self._put_commit("a push", self._build(flat), [self.branch])
        self.pr["head"]["sha"] = self.branch

    def file_at(self, commit_sha, path):
        entry = self.flat[self.objects[commit_sha][1]["tree"]["sha"]].get(path)
        return None if entry is None else (self.objects[entry["sha"]][1].decode(), entry["mode"])

    # ---- the API ----

    def request(self, method, path, token, body=None):
        if method != "GET":
            self.writes.append((method, path))
        route = (method, path.split("?")[0])
        if route == ("GET", "/repos/o/r/installation"):
            if not self.installed:
                raise handler.GitHubError(404, "Not Found")
            return {"id": 55}
        if route == ("POST", "/app/installations/55/access_tokens"):
            assert body["repository_ids"] == [123]
            assert body["permissions"]["contents"] == "write"
            return {"token": "tok"}
        if route == ("GET", "/repos/o/r/pulls/7"):
            return copy.deepcopy(self.pr)
        kind, _, sha = path.rpartition("/")
        if method == "GET" and kind in ("/repos/o/r/git/commits", "/repos/o/r/git/trees",
                                        "/repos/o/r/git/blobs"):
            obj_kind, obj = self.objects[sha]
            if obj_kind == "commit":
                return copy.deepcopy(obj)
            if obj_kind == "tree":
                return {"sha": sha, "tree": copy.deepcopy(obj), "truncated": False}
            return {"content": base64.b64encode(obj).decode(), "encoding": "base64"}
        if route == ("POST", "/repos/o/r/git/blobs"):
            return {"sha": self._put_blob(base64.b64decode(body["content"]))}
        if route == ("POST", "/repos/o/r/git/trees"):
            flat = dict(self.flat[body["base_tree"]])
            for e in body["tree"]:
                flat[e["path"]] = {"mode": e["mode"], "type": e["type"], "sha": e["sha"]}
            return {"sha": self._build(flat)}
        if route == ("POST", "/repos/o/r/git/commits"):
            return {"sha": self._put_commit(body["message"], body["tree"], body["parents"])}
        if route == ("PATCH", "/repos/o/r/git/refs/heads/feature"):
            if self.before_patch:
                self.before_patch(self)
            assert body["force"] is False
            if self.objects[body["sha"]][1]["parents"] != [self.branch]:
                raise handler.GitHubError(422, '{"message":"Update is not a fast forward"}')
            self.branch = body["sha"]
            return {}
        if route == ("GET", "/repos/o/r/branches/feature"):
            return {"commit": {"sha": self.branch, "commit": {"message": self.objects[self.branch][1]["message"]}}}
        raise AssertionError(f"unexpected GitHub call {method} {path}")


class FakeTable:
    """The table, in memory, for the expressions the committer writes."""

    def __init__(self, items):
        self.items = {(i["pk"], i["sk"]): copy.deepcopy(i) for i in items}

    def get_item(self, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": copy.deepcopy(item)} if item else {}

    def query(self, KeyConditionExpression, ExpressionAttributeValues, **_):
        pk, prefix = ExpressionAttributeValues[":pk"], ExpressionAttributeValues[":sk"]
        return {"Items": [copy.deepcopy(v) for (p, s), v in sorted(self.items.items())
                          if p == pk and s.startswith(prefix)]}

    def put_item(self, Item, **_):
        self.items[(Item["pk"], Item["sk"])] = copy.deepcopy(Item)

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues,
                    ConditionExpression=None, ExpressionAttributeNames=None):
        names, values = ExpressionAttributeNames or {}, ExpressionAttributeValues
        item = self.items.get((Key["pk"], Key["sk"]))
        status = (item or {}).get("status")
        ok = {
            None: True,
            "#status = :requested": status == values.get(":requested"),
            "#status = :committing": status == values.get(":committing"),
            "#status IN (:requested, :committing)": status in ("requested", "committing"),
            "attribute_exists(proposed_fix)": item is not None and "proposed_fix" in item,
        }[ConditionExpression]
        if not ok:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        for clause in UpdateExpression.removeprefix("SET ").split(", "):
            lhs, rhs = clause.split(" = ")
            parts = [names.get(p, p) for p in lhs.split(".")]
            target = item
            for p in parts[:-1]:
                target = target[p]
            target[parts[-1]] = copy.deepcopy(values[rhs])

    def events(self, fid):
        return [v for (p, s), v in sorted(self.items.items()) if p == f"PR#gh-1-7#FINDING#{fid}"]


KEY_V1 = 'resource "aws_kms_key" "k" {\n  description = "reports"\n}\n'
KEY_ROTATED = KEY_V1.replace("}\n", "  enable_key_rotation = true\n}\n")
REQUEST_ID = "01J0000000000000000000000A"


def _setup(files=None, fix_path="main.tf", base=KEY_V1, content=KEY_ROTATED, latest="approved",
           verified=True, confirm=True, status="requested", **github_kwargs):
    github = FakeGitHub(files if files is not None else {fix_path: KEY_V1, "other.tf": "x\n"},
                        **github_kwargs)
    fix = {**_fix("kms", base=base, verified=verified, file=fix_path),
           "pk": "PR#gh-1-7", "sk": "FINDING#kms", "rule_id": "CKV_AWS_7"}
    confirmed = [{"file": fix_path, "tip": "kms", "content_sha256": _h(content)}] if confirm else []
    table = FakeTable([
        fix,
        {"pk": "PR#gh-1-7#FINDING#kms", "sk": "EVENT#2026-09-29T00:00:00", "action": latest},
        {"pk": "PR#gh-1-7", "sk": "GITHUB", "repository": "o/r", "repository_id": 123, "pr_number": 7},
        {"pk": "PR#gh-1-7", "sk": f"COMMIT#{REQUEST_ID}", "request_id": REQUEST_ID,
         "requested_by": "konrad@example.com", "status": status, "confirmed": confirmed},
    ])
    fixes = {f"fixes/gh-1-7/kms/{fix_path}": content}
    return github, table, fixes


def _run(github, table, fixes, event=None):
    with patch.object(handler, "_request", side_effect=github.request), \
            patch.object(handler, "app_jwt", return_value="jwt"), \
            patch.object(handler, "_read_fix", side_effect=fixes.get), \
            patch.object(handler, "dynamodb") as mock_dynamodb:
        mock_dynamodb.Table.return_value = table
        return handler.handler(event or {"pr_id": "gh-1-7", "request_id": REQUEST_ID}, None)


def _request_item(table):
    return table.items[("PR#gh-1-7", f"COMMIT#{REQUEST_ID}")]


def test_an_approved_fix_is_committed_on_the_head_and_recorded():
    github, table, fixes = _setup()
    head = github.branch

    result = _run(github, table, fixes)

    assert result["status"] == "committed"
    new = github.branch
    assert new == result["commit_sha"] != head
    commit = github.objects[new][1]
    assert commit["parents"] == [head]
    assert github.file_at(new, "main.tf") == (KEY_ROTATED, "100644")
    assert github.file_at(new, "other.tf") == ("x\n", "100644")

    request = _request_item(table)
    assert request["status"] == "committed" and request["commit_sha"] == new
    assert request["head_sha_before"] == head
    assert request["files"] == [{"file": "main.tf", "outcome": "committed", "reason": None,
                                 "tip": "kms", "chain": ["kms"], "unverified": [], "left_out": []}]
    fix = table.items[("PR#gh-1-7", "FINDING#kms")]
    assert fix["proposed_fix"]["committed"]["sha"] == new
    assert fix["proposed_fix"]["committed"]["request_id"] == REQUEST_ID
    assert fix["status"] == "resolved"
    [_, event] = table.events("kms")
    assert (event["actor"], event["action"]) == ("system", "committed")


def test_the_commit_message_is_code_produced_and_leaves_the_approver_out():
    github, table, fixes = _setup()
    _run(github, table, fixes)
    message = github.objects[github.branch][1]["message"]
    assert message.startswith("Apply 1 approved CascadeSec fix to 1 file\n")
    assert "main.tf: CKV_AWS_7" in message
    assert message.endswith(f"\n{handler.TRAILER}: {REQUEST_ID}\n")
    assert "konrad@example.com" not in message
    assert "unverified" not in message


def test_an_unverified_fix_is_committed_and_labelled():
    github, table, fixes = _setup(verified=False, latest="edited")
    _run(github, table, fixes)
    message = github.objects[github.branch][1]["message"]
    assert "  unverified: CKV_AWS_7" in message and "the scan of this push is their check" in message
    assert _request_item(table)["files"][0]["unverified"] == ["CKV_AWS_7"]


def test_a_file_keeps_its_mode_and_its_directory():
    github, table, fixes = _setup(files={"infra/kms/main.tf": (KEY_V1, "100755")},
                                  fix_path="infra/kms/main.tf")
    _run(github, table, fixes)
    assert github.file_at(github.branch, "infra/kms/main.tf") == (KEY_ROTATED, "100755")


def test_a_push_between_approving_and_committing_holds_the_file():
    """The base check, against GitHub rather than the snapshot: commit B
    appended an alias, and committing A's corrected file would delete it."""
    github, table, fixes = _setup()
    github.push({"main.tf": KEY_V1 + 'resource "aws_kms_alias" "a" {}\n'})
    before = github.branch

    result = _run(github, table, fixes)

    assert result["status"] == "held"
    assert github.branch == before
    assert not [w for w in github.writes if "/git/" in w[1]]
    request = _request_item(table)
    assert request["files"][0]["outcome"] == "held" and "changed since" in request["files"][0]["reason"]
    assert "committed" not in table.items[("PR#gh-1-7", "FINDING#kms")]["proposed_fix"]


def test_a_push_during_the_commit_ends_the_request_with_nothing_written():
    github, table, fixes = _setup()
    github.before_patch = lambda gh: gh.push({"other.tf": "y\n"})

    result = _run(github, table, fixes)

    assert result["status"] == "held" and "branch moved" in result["reason"]
    assert github.file_at(github.branch, "main.tf") == (KEY_V1, "100644")
    assert _request_item(table)["status"] == "held"
    assert "committed" not in table.items[("PR#gh-1-7", "FINDING#kms")]["proposed_fix"]


def test_branch_protection_is_reported_not_worked_around():
    github, table, fixes = _setup()

    def protected(method, path, token, body=None):
        if method == "PATCH":
            raise handler.GitHubError(403, '{"message":"Protected branch update failed"}')
        return github.request(method, path, token, body)

    with patch.object(handler, "_request", side_effect=protected), \
            patch.object(handler, "app_jwt", return_value="jwt"), \
            patch.object(handler, "_read_fix", side_effect=fixes.get), \
            patch.object(handler, "dynamodb") as mock_dynamodb:
        mock_dynamodb.Table.return_value = table
        result = handler.handler({"pr_id": "gh-1-7", "request_id": REQUEST_ID}, None)

    assert result["status"] == "held" and "Protected branch update failed" in result["reason"]


@pytest.mark.parametrize("change, reason", [
    (lambda pr: pr.update(state="closed"), "not open"),
    (lambda pr: pr["head"]["repo"].update(id=999), "fork"),
    (lambda pr: pr["head"].update(repo=None), "fork"),
    (lambda pr: pr["head"].update(ref="main"), "default branch"),
])
def test_a_pull_request_that_cannot_be_committed_to_is_refused_before_any_write(change, reason):
    github, table, fixes = _setup()
    change(github.pr)
    result = _run(github, table, fixes)
    assert result["status"] == "held" and reason in result["reason"]
    assert not [w for w in github.writes if "/git/" in w[1]]


def test_a_repository_without_the_writer_app_is_told_so():
    github, table, fixes = _setup(installed=False)
    result = _run(github, table, fixes)
    assert result["status"] == "held" and "not installed" in result["reason"]


@pytest.mark.parametrize("spec, reason", [
    (("symlink", "../../etc/passwd"), "symlink"),
    (("submodule",), "submodule"),
])
def test_a_link_or_submodule_at_the_path_is_held(spec, reason):
    github, table, fixes = _setup(files={"main.tf": spec})
    result = _run(github, table, fixes)
    assert result["status"] == "held"
    assert reason in _request_item(table)["files"][0]["reason"]


def test_content_the_reviewer_did_not_confirm_is_not_committed():
    # The tip was edited after the preview: same finding, other content.
    github, table, fixes = _setup(confirm=False)
    before = github.branch
    result = _run(github, table, fixes)
    assert result["status"] == "held" and github.branch == before
    assert "not what was confirmed" in _request_item(table)["files"][0]["reason"]


def test_a_file_already_at_the_fix_is_recorded_without_a_commit():
    # A person applied the suggestions, or an earlier request landed it.
    github, table, fixes = _setup(files={"main.tf": KEY_ROTATED})
    before = github.branch
    result = _run(github, table, fixes)
    assert result["status"] == "committed" and github.branch == before
    assert _request_item(table)["files"][0]["outcome"] == "already"
    assert table.items[("PR#gh-1-7", "FINDING#kms")]["proposed_fix"]["committed"]["sha"] == before


def test_a_retry_whose_first_attempt_landed_records_it_without_committing_again():
    github, table, fixes = _setup()
    _run(github, table, fixes)
    landed = github.branch
    # Lambda retries: the request is back at committing, the fixes unrecorded.
    github2, table2, fixes2 = _setup(status="committing")
    github2.objects, github2.flat, github2.branch = github.objects, github.flat, landed
    github2.pr["head"]["sha"] = landed

    result = _run(github2, table2, fixes2)

    assert result == {"status": "committed", "commit_sha": landed}
    assert github2.branch == landed
    assert not [w for w in github2.writes if "/git/" in w[1]]
    assert _request_item(table2)["files"][0]["outcome"] == "committed"
    assert table2.items[("PR#gh-1-7", "FINDING#kms")]["proposed_fix"]["committed"]["sha"] == landed


def test_a_retry_whose_first_attempt_did_not_land_commits():
    github, table, fixes = _setup(status="committing")
    assert _run(github, table, fixes)["status"] == "committed"


def test_a_twin_that_loses_the_race_leaves_the_ending_to_the_winner():
    github, table, fixes = _setup()

    def twin_wins(gh):
        # The twin committed this request first, with the same trailer.
        tree = gh.objects[gh.branch][1]["tree"]["sha"]
        gh.branch = gh._put_commit(f"x\n\n{handler.TRAILER}: {REQUEST_ID}\n", tree, [gh.branch])

    github.before_patch = twin_wins
    result = _run(github, table, fixes)
    assert result == {"skipped": "a concurrent attempt committed this request"}
    assert _request_item(table)["status"] == "committing"


def test_an_unexpected_github_error_is_raised_for_lambda_to_retry():
    github, table, fixes = _setup()

    def broken(method, path, token, body=None):
        if path.endswith("/git/trees") and method == "POST":
            raise handler.GitHubError(502, "Bad Gateway")
        return github.request(method, path, token, body)

    with patch.object(handler, "_request", side_effect=broken), \
            patch.object(handler, "app_jwt", return_value="jwt"), \
            patch.object(handler, "_read_fix", side_effect=fixes.get), \
            patch.object(handler, "dynamodb") as mock_dynamodb:
        mock_dynamodb.Table.return_value = table
        with pytest.raises(handler.GitHubError):
            handler.handler({"pr_id": "gh-1-7", "request_id": REQUEST_ID}, None)
    assert _request_item(table)["status"] == "committing"


@pytest.mark.parametrize("status", ["committed", "held", "failed"])
def test_an_ended_request_is_not_run_again(status):
    github, table, fixes = _setup(status=status)
    assert _run(github, table, fixes) == {"skipped": f"request is already {status}"}
    assert github.writes == []


# ---------- the failure backstop ----------

def _failure(payload):
    return {"detail-type": handler.FAILURE_DETAIL_TYPE,
            "detail": {"requestPayload": payload, "requestContext": {"condition": "RetriesExhausted"},
                       "responsePayload": {"errorMessage": "GitHub 502: Bad Gateway"}}}


def test_a_request_lambda_gave_up_on_is_marked_failed():
    github, table, fixes = _setup(status="committing")
    _run(github, table, fixes, _failure({"pr_id": "gh-1-7", "request_id": REQUEST_ID}))
    request = _request_item(table)
    assert request["status"] == "failed" and "Bad Gateway" in request["reason"]


def test_a_failure_does_not_overwrite_an_ending():
    github, table, fixes = _setup(status="committed")
    _run(github, table, fixes, _failure({"pr_id": "gh-1-7", "request_id": REQUEST_ID}))
    assert _request_item(table)["status"] == "committed"


def test_the_failure_of_a_failure_is_ignored_so_it_cannot_loop():
    github, table, fixes = _setup(status="committing")
    nested = _failure(_failure({"pr_id": "gh-1-7", "request_id": REQUEST_ID}))
    assert _run(github, table, fixes, nested) == {"skipped": "not a commit request"}
    assert _request_item(table)["status"] == "committing"


def test_the_failure_backstop_never_raises():
    with patch.object(handler, "dynamodb") as mock_dynamodb:
        mock_dynamodb.Table.side_effect = RuntimeError("no table")
        result = handler.handler(_failure({"pr_id": "gh-1-7", "request_id": REQUEST_ID}), None)
    assert result == {"skipped": "could not record the failure"}


def test_a_path_cannot_forge_a_trailer_in_the_message():
    plan = {"file": f"x.tf\n{handler.TRAILER}: someone-else",
            "chain": [{"rule_id": "R", "verified": True}]}
    message = handler.commit_message("gh-1-7", REQUEST_ID, [plan])
    assert not handler._has_trailer(message, "someone-else")
    assert handler._has_trailer(message, REQUEST_ID)
