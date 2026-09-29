"""github-committer Lambda (docs/write-back-spec.md).

Commits a PR's approved fixes to its branch as one commit, when a member of
the committers group asks for it in the dashboard. review-api records the
request (COMMIT#<request_id>) and invokes this asynchronously; API Gateway
cannot reach it, and review-api never signs (§2, W1).

It acts as the second GitHub App, "CascadeSec Fixes", whose key is the only
one with Contents write (§4, W2). The JWT is signed by KMS, as
github-gateway's is, and exchanged for a token narrowed to one repository.
An installation is per repository: installing the App is the owner's
opt-in to write-back, and a repository without it is told so.

In order (§6), and nothing is written until every check has passed:

  1. the request moves requested -> committing, conditionally;
  2. the PR is read fresh from GitHub, and a closed PR, a fork, or a head
     that is the default branch is refused;
  3. plan_commit decides per file, reading the head from GitHub's tree --
     never the S3 snapshot -- and refusing a symlink or submodule there;
     a file whose tip or content is not what the reviewer confirmed is
     held;
  4. one commit through the Git Data API, parented on the head, and a ref
     update with force false: the compare-and-swap. A branch that moved
     meanwhile ends the request with nothing written, and is not retried
     (W8): a retry means re-checking every base, and asking again does.

Then every committed fix records the commit and gets a "committed"
ReviewEvent, so nothing lands on a branch off the books (§7). The commit's
push is scanned by the v3 pipeline like any other.

The commit message is code-produced only: rule ids, counts, which fixes
are unverified, a dashboard link and a CascadeSec-Request trailer. No
model prose, and not the approver's identity (W5), which the audit log
holds and a public commit would keep forever.

Invoked by Lambda (async, retried twice) with {pr_id, request_id}, and by
EventBridge with Lambda's failure record once the retries are spent, to
mark the request failed. A retry finds the request "committing" and looks
for its own trailer on the branch before doing anything.

plan_commit, below, is pure, and review-api carries an identical copy for
the dashboard's preview; corpus/test_corpus.py keeps the two the same.
"""

import base64
import difflib
import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
KMS_KEY_ID = os.environ.get("KMS_KEY_ID")
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "").rstrip("/")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
METRIC_NAMESPACE = "IaCPosture"

GITHUB_API = "https://api.github.com"
USER_AGENT = "CascadeSec-Fixes"
# The last line of every commit this makes. How a retry recognises its own
# commit on the branch, and how a reader gets from a commit to its request.
TRAILER = "CascadeSec-Request"
FAILURE_DETAIL_TYPE = "Lambda Function Invocation Result - Failure"
# Regular files, by git mode. Anything else at a path is not committed over.
FILE_MODES = {"100644", "100755"}

kms = boto3.client("kms")
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")


class GitHubError(Exception):
    def __init__(self, status, message):
        super().__init__(f"GitHub {status}: {message}")
        self.status = status
        self.message = message


class Refused(Exception):
    """The request ends "held" with this reason, and nothing was written."""


def handler(event, context):
    if event.get("detail-type") == FAILURE_DETAIL_TYPE:
        return on_failure(event)
    return commit(event["pr_id"], event["request_id"])


# ======================================================================
# Acting as the writer App (the same mechanism as github-gateway's)
# ======================================================================

def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def app_jwt(now=None):
    """The writer App's JWT, RS256, signed by KMS. See github-gateway's
    app_jwt: only the key and the App id differ."""
    now = int(time.time()) if now is None else now
    iss = int(GITHUB_APP_ID) if GITHUB_APP_ID.isdigit() else GITHUB_APP_ID
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": iss},
                                separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode("ascii")
    signature = kms.sign(
        KeyId=KMS_KEY_ID,
        Message=signing_input,
        MessageType="RAW",
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )["Signature"]
    return f"{header}.{claims}.{_b64url(signature)}"


def installation_token(repository, repository_id):
    """A token for this one repository, with Contents write and nothing it
    does not use. The installation is looked up rather than stored: it is
    the writer App's, which the pipeline never sees, and its absence is the
    answer to "has the owner opted in"."""
    jwt = app_jwt()
    try:
        installation = _request("GET", f"/repos/{repository}/installation", jwt)
    except GitHubError as e:
        if e.status == 404:
            raise Refused("write-back is not installed on this repository; install the "
                          "CascadeSec Fixes App on it to commit fixes") from None
        raise
    response = _request(
        "POST", f"/app/installations/{int(installation['id'])}/access_tokens", jwt,
        {"repository_ids": [int(repository_id)],
         "permissions": {"contents": "write", "pull_requests": "read", "metadata": "read"}},
    )
    return response["token"]


def _request(method, path, token, body=None):
    """One GitHub API call, parsed JSON back."""
    url = path if path.startswith("https://") else GITHUB_API + path
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
        **({"Content-Type": "application/json"} if data is not None else {}),
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise GitHubError(e.code, detail) from None
    return json.loads(payload) if payload else None


# ======================================================================
# commit
# ======================================================================

def commit(pr_id, request_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    key = {"pk": f"PR#{pr_id}", "sk": f"COMMIT#{request_id}"}
    request = table.get_item(Key=key).get("Item")
    if request is None:
        logger.error("commit request %s on %s does not exist", request_id, pr_id)
        return {"skipped": "no such request"}
    if request["status"] not in ("requested", "committing"):
        return {"skipped": f"request is already {request['status']}"}

    # Claim it. Losing means an earlier attempt claimed it and did not
    # finish -- Lambda's retry -- or a twin delivery is running now. Either
    # way the branch is checked for this request's commit before anything.
    retry = False
    try:
        table.update_item(
            Key=key,
            UpdateExpression="SET #status = :committing, updated_at = :now",
            ConditionExpression="#status = :requested",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":committing": "committing", ":requested": "requested",
                                       ":now": _now()},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        retry = True

    meta = table.get_item(Key={"pk": f"PR#{pr_id}", "sk": "GITHUB"}).get("Item")
    try:
        if meta is None:
            raise Refused("this PR has no recorded repository; push to it once")
        outcome = write(pr_id, request, meta, retry)
    except Refused as e:
        logger.info("commit request %s held: %s", request_id, e)
        _finish(table, key, "held", reason=str(e))
        _emit_metrics({"CommitsCreated": 0, "FilesCommitted": 0, "FilesHeldFromCommit": 0},
                      pr_id=pr_id, request_id=request_id)
        return {"status": "held", "reason": str(e)}
    if outcome is None:
        return {"skipped": "a concurrent attempt committed this request"}

    plans, commit_sha, head_sha = outcome
    record_commit(table, pr_id, request, plans, commit_sha, head_sha)
    landed = [p for p in plans if p["outcome"] in ("committed", "already")]
    status = "committed" if landed else "held"
    _finish(table, key, status, commit_sha=commit_sha, head_sha_before=head_sha,
            files=[_file_record(p) for p in plans],
            reason=None if landed else "nothing could be committed; see each file")
    committed = sum(1 for p in plans if p["outcome"] == "committed")
    _emit_metrics({"CommitsCreated": 1 if committed else 0,
                   "FilesCommitted": committed,
                   "FilesHeldFromCommit": sum(1 for p in plans if p["outcome"] == "held")},
                  pr_id=pr_id, request_id=request_id)
    return {"status": status, "commit_sha": commit_sha}


def write(pr_id, request, meta, retry):
    """Everything that talks to GitHub. Returns (plans, commit_sha, head
    sha before), or None if a twin of this invocation committed first.
    Raises Refused for every refusal, before anything is written."""
    repo = meta["repository"]
    token = installation_token(repo, meta["repository_id"])
    pr = _request("GET", f"/repos/{repo}/pulls/{int(meta['pr_number'])}", token)
    _check_pull_request(pr)
    head_sha, ref = pr["head"]["sha"], pr["head"]["ref"]
    head_commit = _request("GET", f"/repos/{repo}/git/commits/{head_sha}", token)
    # A retry whose first attempt landed: the head is this request's commit,
    # every file in it plans as "already", and it is recorded, not redone.
    landed = retry and _has_trailer(head_commit.get("message") or "", request["request_id"])

    tree = _Tree(repo, token, head_commit["tree"]["sha"])
    findings = _query_findings(pr_id)
    plans = plan_commit(pr_id, findings, _latest_actions(pr_id, findings),
                        _read_fix, lambda path: _read_head(repo, token, tree, path))

    confirmed = {(c["file"], c["tip"], c["content_sha256"]) for c in request.get("confirmed") or []}
    for plan in plans:
        if plan["outcome"] == "commit" and (
                landed or (plan["file"], plan["tip"], plan["content_sha256"]) not in confirmed):
            plan.update(outcome="held", reason=(
                "not in the commit this request made" if landed else
                "not what was confirmed: the fixes or the file changed after the plan was "
                "shown; review it again"))
        elif plan["outcome"] == "already" and landed:
            plan["outcome"] = "committed"

    if landed:
        return plans, head_sha, head_sha

    to_write = [p for p in plans if p["outcome"] == "commit"]
    if not to_write:
        return plans, None, head_sha

    entries = []
    for plan in to_write:
        blob = _request("POST", f"/repos/{repo}/git/blobs", token, {
            "content": base64.b64encode(plan["content"].encode("utf-8")).decode("ascii"),
            "encoding": "base64",
        })
        # The path's existing mode: an executable stays executable.
        entries.append({"path": plan["file"], "mode": tree.entry(plan["file"])["mode"],
                        "type": "blob", "sha": blob["sha"]})
    new_tree = _request("POST", f"/repos/{repo}/git/trees", token,
                        {"base_tree": head_commit["tree"]["sha"], "tree": entries})
    new_commit = _request("POST", f"/repos/{repo}/git/commits", token, {
        "message": commit_message(pr_id, request["request_id"], to_write),
        "tree": new_tree["sha"],
        "parents": [head_sha],
    })
    try:
        _request("PATCH", f"/repos/{repo}/git/refs/heads/{urllib.parse.quote(ref, safe='/')}",
                 token, {"sha": new_commit["sha"], "force": False})
    except GitHubError as e:
        if e.status not in (403, 409, 422):
            raise
        # A twin delivery of this same request may have won the race. Its
        # commit is on the branch with this trailer, and it will record it.
        now_head = _request("GET", f"/repos/{repo}/branches/{urllib.parse.quote(ref, safe='')}",
                            token)
        if _has_trailer((now_head.get("commit") or {}).get("commit", {}).get("message") or "",
                        request["request_id"]):
            return None
        if e.status == 422 and "fast forward" in e.message.lower():
            raise Refused("the branch moved while committing; nothing was written. "
                          "Ask again to re-check every file against it") from None
        # Branch protection and rulesets answer here. Never worked around.
        raise Refused(f"GitHub refused the push: {e.message[:300]}") from None

    for plan in to_write:
        plan["outcome"] = "committed"
    return plans, new_commit["sha"], head_sha


def _check_pull_request(pr):
    if pr.get("state") != "open":
        raise Refused("the pull request is not open")
    head_repo = (pr.get("head") or {}).get("repo") or {}
    base_repo = (pr.get("base") or {}).get("repo") or {}
    # An installation token cannot push to a fork, and a fork's owner never
    # opted in (W7). The suggestions remain the path there.
    if not head_repo or head_repo.get("id") != base_repo.get("id"):
        raise Refused("the pull request is from a fork; apply the suggestions instead")
    if pr["head"]["ref"] == base_repo.get("default_branch"):
        raise Refused("the pull request's head is the default branch, which is never committed to")


def _has_trailer(message, request_id):
    return re.search(rf"^{TRAILER}: {re.escape(request_id)}$", message, re.M) is not None


class _Tree:
    """Tree entries at the head commit, walked one directory at a time.

    Not the recursive listing, which GitHub truncates on a large repository
    and then answers only part of. Each directory is read at most once.
    """

    def __init__(self, repo, token, root_sha):
        self.repo, self.token, self.root_sha = repo, token, root_sha
        self._listings = {}

    def _listing(self, sha):
        if sha not in self._listings:
            tree = _request("GET", f"/repos/{self.repo}/git/trees/{sha}", self.token)
            if tree.get("truncated"):
                raise Refused("a directory at the PR head is too large to read")
            self._listings[sha] = {e["path"]: e for e in tree.get("tree") or []}
        return self._listings[sha]

    def entry(self, path):
        """The tree entry at `path` -- {path, mode, type, sha} -- or None."""
        parts = path.split("/")
        sha = self.root_sha
        for depth, name in enumerate(parts):
            entry = self._listing(sha).get(name)
            if entry is None:
                return None
            if depth < len(parts) - 1:
                if entry.get("type") != "tree":
                    return None
                sha = entry["sha"]
        return entry


def _read_head(repo, token, tree, path):
    """(the file at the PR head, None), or (None, why it is not committed
    over). A link's target is what a hostile repository aims elsewhere, so
    a symlink is refused rather than followed, as the snapshot skips them."""
    if path.startswith("/") or any(p in ("", ".", "..") for p in path.split("/")):
        return None, "not a plain path in the repository"
    entry = tree.entry(path)
    if entry is None:
        return None, "the file is not at the PR head"
    if entry.get("mode") == "120000":
        return None, "a symlink at the PR head"
    if entry.get("type") == "commit":
        return None, "a submodule at the PR head"
    if entry.get("type") != "blob" or entry.get("mode") not in FILE_MODES:
        return None, "not a regular file at the PR head"
    blob = _request("GET", f"/repos/{repo}/git/blobs/{entry['sha']}", token)
    try:
        return base64.b64decode(blob["content"]).decode("utf-8"), None
    except (ValueError, UnicodeDecodeError):
        return None, "not UTF-8 text at the PR head"


def _read_fix(key):
    try:
        return s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=key)["Body"].read().decode("utf-8")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchKey":
            raise
        return None


def commit_message(pr_id, request_id, plans):
    """Code-produced only (integrations-spec §2.3): rule ids, counts, which
    fixes are unverified, a link, the trailer. Paths are the repository's
    own, with anything that could start a new line replaced, so no path can
    forge a trailer."""
    fixes = sum(len(p["chain"]) for p in plans)
    lines = [f"Apply {fixes} approved CascadeSec fix{'' if fixes == 1 else 'es'} "
             f"to {len(plans)} file{'' if len(plans) == 1 else 's'}", ""]
    any_unverified = False
    for plan in plans:
        path = re.sub(r"[\x00-\x1f\x7f]", "?", plan["file"])
        lines.append(f"{path}: {', '.join(c['rule_id'] for c in plan['chain'])}")
        unverified = [c["rule_id"] for c in plan["chain"] if not c["verified"]]
        if unverified:
            any_unverified = True
            lines.append(f"  unverified: {', '.join(unverified)}")
    lines.append("")
    lines.append("Each file is its fixes' corrected file, committed over the version they were "
                 "drafted on.")
    if any_unverified:
        lines.append("Unverified fixes were approved by a reviewer without passing the "
                     "self-check (edited, or held); the scan of this push is their check.")
    if DASHBOARD_URL:
        lines += ["", f"Review: {DASHBOARD_URL}/prs/{pr_id}"]
    lines += ["", f"{TRAILER}: {request_id}"]
    return "\n".join(lines) + "\n"


# ---------- the record (§7) ----------

def record_commit(table, pr_id, request, plans, commit_sha, head_sha):
    """Every fix in a landed file records the commit it landed in, and gets
    a "committed" ReviewEvent with actor system. Status stays resolved; the
    push scan marks the findings no_longer_detected. A file found already
    committed records the head it was found in."""
    now = _now()
    for plan in plans:
        if plan["outcome"] not in ("committed", "already"):
            continue
        sha = commit_sha if plan["outcome"] == "committed" else head_sha
        for link in plan["chain"]:
            table.update_item(
                Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{link['finding_id']}"},
                UpdateExpression="SET proposed_fix.committed = :committed, updated_at = :now",
                ConditionExpression="attribute_exists(proposed_fix)",
                ExpressionAttributeValues={
                    ":committed": {"sha": sha, "request_id": request["request_id"], "at": now},
                    ":now": now,
                },
            )
            notes = (f"Committed to the PR branch in {sha[:12]}" if plan["outcome"] == "committed"
                     else f"Already on the PR branch at {sha[:12]}")
            table.put_item(Item={
                "pk": f"PR#{pr_id}#FINDING#{link['finding_id']}",
                # Suffixed like review-api's system events, so it cannot
                # collide with a decision made in the same instant.
                "sk": f"EVENT#{now}#committed",
                "finding_id": link["finding_id"],
                "pr_id": pr_id,
                "actor": "system",
                "action": "committed",
                "notes": (f"{notes}, with {len(plan['chain'])} fix(es) on {plan['file']}; "
                          f"commit request {request['request_id']} by {request['requested_by']}."),
                "edited_diff": None,
                "created_at": now,
            })


def _file_record(plan):
    return {
        "file": plan["file"],
        "outcome": plan["outcome"],
        "reason": plan["reason"],
        "tip": plan["tip"],
        "chain": [c["finding_id"] for c in plan["chain"]],
        "unverified": [c["rule_id"] for c in plan["chain"] if not c["verified"]],
        "left_out": plan["left_out"],
    }


def _finish(table, key, status, **fields):
    """End the request. Conditional on "committing", so a late finisher --
    the failure backstop, or a twin -- cannot overwrite an ending."""
    fields = {k: v for k, v in fields.items() if v is not None}
    names = {"#status": "status", **{f"#{k}": k for k in fields}}
    sets = ["#status = :status", "updated_at = :now"] + [f"#{k} = :{k}" for k in fields]
    try:
        table.update_item(
            Key=key,
            UpdateExpression="SET " + ", ".join(sets),
            ConditionExpression="#status = :committing",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={":status": status, ":now": _now(), ":committing": "committing",
                                       **{f":{k}": v for k, v in fields.items()}},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        logger.warning("request %s had already ended; left as it was", key["sk"])


# ---------- reading the table ----------

def _query_all(table, **kwargs):
    items = []
    while True:
        response = table.query(**kwargs)
        items.extend(response.get("Items", []))
        if not response.get("LastEvaluatedKey"):
            return items
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]


def _query_findings(pr_id):
    return _query_all(
        dynamodb.Table(DYNAMODB_TABLE),
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": f"PR#{pr_id}", ":sk": "FINDING#"},
    )


def _latest_actions(pr_id, findings):
    """{finding_id: its latest ReviewEvent's action}, as review-api reads it,
    for the findings plan_commit could consider."""
    table = dynamodb.Table(DYNAMODB_TABLE)
    latest = {}
    for f in findings:
        fix = f.get("proposed_fix") or {}
        if not fix.get("diff") or fix.get("committed") or f.get("no_longer_detected"):
            continue
        events = _query_all(
            table,
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
            ExpressionAttributeValues={":pk": f"PR#{pr_id}#FINDING#{f['finding_id']}",
                                       ":sk": "EVENT#"},
        )
        if events:
            latest[f["finding_id"]] = max(events, key=lambda e: e["sk"])["action"]
    return latest


# ======================================================================
# The failure backstop (EventBridge)
# ======================================================================

def on_failure(event):
    """Mark a request failed once Lambda has given up on it, so the
    dashboard does not poll a "committing" request forever.

    Never raises. This runs through the same destination as any other
    invocation, so a failure here would come back as another failure event;
    and a record whose payload is itself a failure record is ignored, which
    is what stops that from looping.
    """
    try:
        detail = event.get("detail") or {}
        payload = detail.get("requestPayload") or {}
        if "detail-type" in payload or not payload.get("request_id") or not payload.get("pr_id"):
            return {"skipped": "not a commit request"}
        error = (detail.get("responsePayload") or {}).get("errorMessage") \
            or (detail.get("requestContext") or {}).get("condition") or "unknown"
        table = dynamodb.Table(DYNAMODB_TABLE)
        table.update_item(
            Key={"pk": f"PR#{payload['pr_id']}", "sk": f"COMMIT#{payload['request_id']}"},
            UpdateExpression="SET #status = :failed, reason = :reason, updated_at = :now",
            ConditionExpression="#status IN (:requested, :committing)",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":failed": "failed", ":requested": "requested", ":committing": "committing",
                ":reason": f"the committer failed after its retries ({str(error)[:200]}); "
                           "check the branch before asking again",
                ":now": _now(),
            },
        )
        _emit_metrics({"CommitsFailed": 1}, pr_id=payload["pr_id"], request_id=payload["request_id"])
        return {"failed": payload["request_id"]}
    except Exception:
        logger.exception("could not record a failed commit request")
        return {"skipped": "could not record the failure"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _emit_metrics(metrics, **context):
    """One Embedded Metric Format line; see review-api's _emit_metrics."""
    dimensions = {"Environment": ENVIRONMENT}
    print(json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [sorted(dimensions)],
                "Metrics": [{"Name": name, "Unit": "Count"} for name in metrics],
            }],
        },
        **dimensions,
        **metrics,
        **context,
    }))


# ======================================================================
# What gets committed (write-back-spec §5). Copied into review-api; keep
# the copies identical -- corpus/test_corpus.py asserts it.
# ======================================================================

def plan_commit(pr_id, findings, latest_actions, read_fix, read_head):
    """Per file with an approved fix, what committing it would do.

    `findings` are the PR's finding records, `latest_actions` maps a
    finding id to the action of its latest ReviewEvent, `read_fix(key)` is a
    fix's corrected file from S3 (None if missing), and `read_head(path)` is
    (the file at the PR head, None) or (None, why it cannot be read). The
    dashboard's preview reads the head from the S3 snapshot; the committer
    reads it from GitHub, and refuses a symlink or a submodule there.

    Approved means the latest ReviewEvent is "approved" or "edited" -- the
    event log, not status, because status is a lossy cache of the last
    resolving action (fix-chain-review-spec §1). A committed fix, and one
    the scan no longer reports, is not planned again.

    Per file, not per finding: fixes are chained, and only a chain's last
    corrected file was built with every earlier fix in it. The tip is the
    end of the longest chain whose every link is approved and unchanged
    since the chain was built. Its content is a whole file drafted on one
    version, so it may only replace that version: base_sha256 must be the
    head's hash, or committing it would revert whatever changed in between
    (write-back-spec §8). A head already equal to the tip's content is
    "already" -- a retried request, or a person who applied the suggestions.

    Returns [{file, outcome, reason, tip, chain, left_out, content,
    content_sha256, diff}] sorted by file. outcome is "commit", "already" or
    "held"; reason says why a file is held. content_sha256 is what a
    reviewer confirms along with the tip: an edit keeps the finding id and
    changes the content, and the commit has to be the content they saw. chain lists the tip's links with whether each was
    verified by its self-check (an edit never is, write-back-spec §5.5).
    left_out names approved fixes the tip does not carry.
    """
    approved_by_file = {}
    for f in findings:
        fix = f.get("proposed_fix") or {}
        if (fix.get("diff") and not fix.get("committed") and not f.get("no_longer_detected")
                and latest_actions.get(f["finding_id"]) in ("approved", "edited")):
            approved_by_file.setdefault(f["file"], {})[f["finding_id"]] = f

    plans = []
    for path in sorted(approved_by_file):
        approved = approved_by_file[path]
        plan = {"file": path, "outcome": "held", "reason": None, "tip": None, "chain": [],
                "left_out": [], "content": None, "content_sha256": None, "diff": None}
        plans.append(plan)

        tip = approved_tip(approved)
        if tip is None:
            plan["reason"] = ("every approved fix here was drafted on top of one that is not "
                              "approved, or has changed since; see the dashboard")
            plan["left_out"] = sorted(f["rule_id"] for f in approved.values())
            continue
        chain = [link["finding_id"] for link in tip["proposed_fix"].get("applies_after") or []]
        chain.append(tip["finding_id"])
        plan["tip"] = tip["finding_id"]
        plan["chain"] = [{"finding_id": i, "rule_id": approved[i]["rule_id"],
                          "verified": bool(approved[i]["proposed_fix"].get("self_check_passed")),
                          "edited": latest_actions[i] == "edited"} for i in chain]
        plan["left_out"] = sorted(approved[i]["rule_id"] for i in approved if i not in chain)

        head, why = read_head(path)
        if head is None:
            plan["reason"] = why
            continue
        content = read_fix(f"fixes/{pr_id}/{tip['finding_id']}/{path}")
        if content is None:
            plan["reason"] = "the fix's corrected file is missing"
            continue
        if _content_sha256(head) == _content_sha256(content):
            plan["outcome"] = "already"
            continue
        base = tip["proposed_fix"].get("base_sha256")
        if not base:
            plan["reason"] = "drafted before fixes recorded their base; run Draft fixes again"
            continue
        if base != _content_sha256(head):
            plan["reason"] = ("the file has changed since these fixes were drafted; "
                              "run Draft fixes again")
            continue
        plan.update(outcome="commit", content=content, content_sha256=_content_sha256(content),
                    diff=_commit_diff(head, content, path))
    return plans


def approved_tip(approved):
    """The end of the longest chain made only of approved fixes, or None.

    github-gateway's chain_tip with "approved" in place of "verified". A
    chain is valid if every link is approved and its diff is the one the
    chain was built on (applies_after records each link's hash): a link
    edited since, or never approved, means the tip's file carries a change
    nobody said yes to. Links from before the chain carried hashes are bare
    ids and cannot be checked, so they fail closed. Ties on length go to
    the larger finding id, as chain_tip's do.
    """
    def valid(fix):
        for link in fix["proposed_fix"].get("applies_after") or []:
            if not isinstance(link, dict):
                return False
            prior = approved.get(link.get("finding_id"))
            if prior is None or _diff_sha256(prior["proposed_fix"]["diff"]) != link.get("diff_sha256"):
                return False
        return True

    candidates = [f for f in approved.values() if valid(f)]
    if not candidates:
        return None
    return max(candidates, key=lambda f: (len(f["proposed_fix"].get("applies_after") or []),
                                          f["finding_id"]))


def _commit_diff(head, content, path):
    """What the reviewer confirms: the head to the tip, the whole change the
    commit makes to this file -- not any one fix's diff, which is in the
    line numbers of an intermediate file."""
    return "".join(difflib.unified_diff(
        head.splitlines(keepends=True), content.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}",
    ))


def _diff_sha256(diff_text):
    """Must stay identical to remediation-agent's helper of the same name."""
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


def _content_sha256(content):
    """Must stay identical to remediation-agent's helper of the same name,
    which records the hash of the file a chain was drafted on."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
