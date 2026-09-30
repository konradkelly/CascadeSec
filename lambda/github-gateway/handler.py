"""github-gateway Lambda (docs/ci-integration-spec.md §4).

The only code that acts as the GitHub App. It never holds the App's private
key: the JWT that proves it is the App is signed by KMS (kms:Sign on a key
whose material was imported and cannot be read back), and exchanged for an
installation token scoped to one repository and to the permissions the step
needs. Every other stage of the pipeline is unchanged and knows nothing about
GitHub.

Invoked by the state machine with an "action", and by EventBridge when an
execution ends badly:

  fetch         open an in-progress check run; snapshot the PR head from the
                repository tarball into scans/<pr_id>/; store the PR's changed
                files and patch hunks for report
  select_files  on a Draft fixes run, the changed files that hold a mapped
                finding -- what the Remediate Map iterates
  report        complete the check run: summary, annotations on the lines the
                PR adds, the Draft fixes button; on a fixes run, post each
                file's verified fix as suggested changes
  (EventBridge) an execution FAILED, TIMED_OUT or was ABORTED: complete its
                check run as neutral, so none is left spinning (spec §6.3)

Nothing a model wrote reaches GitHub. Suggestions are diffs that passed the
self-check; annotations and the summary are scanner text, rule ids and
counts. A fix's rationale, assumptions and questions stay in the dashboard
(spec §6.1).
"""

import base64
import difflib
import hashlib
import html
import json
import logging
import os
import posixpath
import re
import tarfile
import time
import urllib.error
import urllib.request

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
# The check run's name, and how webhook-receiver recognises a check_run event
# as ours. Must match webhook-receiver's CHECK_NAME.
CHECK_NAME = "CascadeSec"
DRAFT_FIXES_ACTION = "draft_fixes"
# The button that commits a Draft fixes run's offer (github-first-review-
# spec §3). Must match webhook-receiver's COMMIT_FIXES_ACTION.
COMMIT_FIXES_ACTION = "commit_fixes"
# Set once write-back is deployed (terraform: var.github_writer_app_id):
# before then there is no committer for a click to reach.
COMMIT_FIXES_ENABLED = bool(os.environ.get("COMMIT_FIXES_ENABLED"))

# Over any of these the check completes as "too large to scan" and no scan
# runs: a partial snapshot looks exactly like a clean one for the files it
# left out (spec §4.2). Set generously; PugetScope's whole tarball is ~2MB.
MAX_TARBALL_BYTES = 200 * 1024 * 1024
MAX_SNAPSHOT_FILES = 3000
MAX_SNAPSHOT_BYTES = 50 * 1024 * 1024
# changed_files rides in the execution state, which is capped at 256KB.
MAX_CHANGED_FILES = 1000
# The Checks API takes at most 50 annotations per request.
ANNOTATIONS_PER_REQUEST = 50

# ---------- what the scanner opens (a copy; see corpus/test_corpus.py) ----------

# Must match iac-scanner's SNAPSHOT_SUFFIXES and scripts/scan.py's; corpus/
# test_corpus.py asserts every copy agrees. An uploader that drifts from the
# scanner loses files silently: absent from the snapshot, absent from the
# findings, and nothing reports it.
SNAPSHOT_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json",
                     ".tofu", ".tofu.json", ".yaml", ".yml", ".bicep")

# Must match iac-scanner's ARM_SCHEMA_RE; corpus/test_corpus.py asserts it.
ARM_SCHEMA_RE = re.compile(r'"\$schema"\s*:\s*"[^"]*deploymentTemplate\.json')

# Must match iac-scanner's CFN_MARKER_RE; corpus/test_corpus.py asserts it.
CFN_MARKER_RE = re.compile(r'"AWSTemplateFormatVersion"\s*:')

# Must match scripts/scan.py's SKIP_DIRS; corpus/test_corpus.py asserts it.
# cdk.out by decision, not as noise: multi-iac-spec §7.1.
SKIP_DIRS = {".terraform", ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             "cdk.out"}

kms = boto3.client("kms")
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")


class GitHubError(Exception):
    def __init__(self, status, message):
        super().__init__(f"GitHub {status}: {message}")
        self.status = status


class TooLarge(Exception):
    """The repository is over a snapshot limit; nothing is scanned."""


def handler(event, context):
    if event.get("detail-type") == "Step Functions Execution Status Change":
        return on_execution_failed(event)
    action = event.get("action")
    if action == "fetch":
        return fetch(event)
    if action == "select_files":
        return select_files(event)
    if action == "report":
        return report(event)
    if action == "report_commit":
        return report_commit(event)
    raise ValueError(f"unknown action {action!r}")


# ======================================================================
# Acting as the App
# ======================================================================

def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def app_jwt(now=None):
    """The App's JWT, RS256, signed by KMS.

    The header and claims are ordinary JSON; only the signature needs the
    key, and kms:Sign produces exactly the PKCS#1 v1.5 SHA-256 signature
    RS256 is. iat is backdated a minute and exp kept under GitHub's ten, as
    GitHub recommends for clock drift.
    """
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


def installation_token(github, permissions):
    """A token for this installation, narrowed to one repository and to
    `permissions`. The App may be installed on many repositories; a step
    that reads one PR has no business holding a token for the others."""
    body = {"repository_ids": [int(github["repository_id"])], "permissions": permissions}
    response = _request(
        "POST", f"/app/installations/{int(github['installation_id'])}/access_tokens",
        app_jwt(), body,
    )
    return response["token"]


def _request(method, path, token, body=None, *, raw=False):
    """One GitHub API call. Returns parsed JSON, or (body, headers) if raw."""
    url = path if path.startswith("https://") else GITHUB_API + path
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": CHECK_NAME,
        "X-GitHub-Api-Version": "2022-11-28",
        **({"Content-Type": "application/json"} if data is not None else {}),
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
            headers = response.headers
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise GitHubError(e.code, f"{method} {path}: {detail}") from None
    if raw:
        return payload, headers
    return json.loads(payload) if payload else None


def _paginate(path, token, key=None):
    """Every page of a list endpoint, following the Link header."""
    url = path + ("&" if "?" in path else "?") + "per_page=100"
    items = []
    while url:
        payload, headers = _request("GET", url, token, raw=True)
        page = json.loads(payload)
        items.extend(page[key] if key else page)
        url = _next_link(headers.get("Link", ""))
    return items


def _next_link(link_header):
    for part in link_header.split(","):
        match = re.search(r'<([^>]+)>;\s*rel="next"', part)
        if match:
            return match.group(1)
    return None


# ======================================================================
# fetch
# ======================================================================

def fetch(event):
    github = event["github"]
    pr_id = event["pr_id"]
    trigger = github.get("trigger", "push")
    token = installation_token(github, {
        "contents": "read", "pull_requests": "read", "checks": "write", "metadata": "read",
    })

    check_run = _request("POST", f"/repos/{github['repository']}/check-runs", token, {
        "name": CHECK_NAME,
        "head_sha": github["head_sha"],
        "status": "in_progress",
        # How the failure handler finds this run again: EventBridge's event
        # carries the execution name and input, not the execution's state.
        "external_id": event["execution_name"],
        **({"details_url": f"{DASHBOARD_URL}/prs/{pr_id}"} if DASHBOARD_URL else {}),
        "output": {
            "title": "Drafting fixes" if trigger == "fixes" else "Scanning",
            "summary": ("Drafting and self-checking fixes for findings in the files this PR changes."
                        if trigger == "fixes" else
                        "Scanning the infrastructure-as-code at this commit."),
        },
    })
    result = {"check_run_id": check_run["id"], "kept_count": 0, "changed_files": [], "reason": None}

    try:
        kept = download_snapshot(github, token)
    except TooLarge as e:
        logger.warning("%s: too large to scan: %s", pr_id, e)
        return {**result, "status": "too_large", "reason": str(e)}
    if not kept:
        return {**result, "status": "empty",
                "reason": "No infrastructure-as-code files at this commit."}

    replace_snapshot(pr_id, kept)

    pr_files = _paginate(f"/repos/{github['repository']}/pulls/{int(github['pr_number'])}/files", token)
    s3.put_object(
        Bucket=ARTIFACTS_BUCKET, Key=files_key(pr_id, github["head_sha"]),
        Body=json.dumps([{"filename": f["filename"], "status": f["status"], "patch": f.get("patch")}
                         for f in pr_files]).encode(),
        ContentType="application/json",
    )
    changed = sorted(f["filename"] for f in pr_files
                     if f["status"] != "removed" and f["filename"] in kept)
    if len(changed) > MAX_CHANGED_FILES:
        return {**result, "status": "too_large", "kept_count": len(kept),
                "reason": f"{len(changed)} changed IaC files, over the {MAX_CHANGED_FILES} limit."}

    logger.info("%s: snapshot of %d file(s), %d changed", pr_id, len(kept), len(changed))
    return {**result, "status": "ok", "kept_count": len(kept), "changed_files": changed}


def files_key(pr_id, head_sha):
    return f"github/{pr_id}/{head_sha}/files.json"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The tarball endpoint redirects to codeload with a short-lived URL that
    carries its own authorisation. Following it with urllib would forward the
    installation token to the second host; stop, and follow it bare."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _CappedReader:
    """A file-like wrapper that raises once more than `limit` bytes are read,
    so a huge tarball fails fast instead of filling memory."""

    def __init__(self, raw, limit):
        self.raw, self.limit, self.read_bytes = raw, limit, 0

    def read(self, size=-1):
        chunk = self.raw.read(size)
        self.read_bytes += len(chunk)
        if self.read_bytes > self.limit:
            raise TooLarge(f"repository tarball over {self.limit // (1024 * 1024)}MB")
        return chunk


def download_snapshot(github, token):
    """{repo path: bytes} for every file at head_sha the scanner would open."""
    url = f"{GITHUB_API}/repos/{github['repository']}/tarball/{github['head_sha']}"
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "User-Agent": CHECK_NAME,
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        response = opener.open(request, timeout=30)
        location = None
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307, 308):
            raise GitHubError(e.code, f"tarball: {e.read()[:300]!r}") from None
        location = e.headers["Location"]
    if location is not None:
        response = urllib.request.urlopen(
            urllib.request.Request(location, headers={"User-Agent": CHECK_NAME}), timeout=60)
    with response:
        return read_snapshot(_CappedReader(response, MAX_TARBALL_BYTES))


def read_snapshot(fileobj):
    """Stream a repository tarball and keep what the scanner would open.

    Nothing is extracted to disk and no member's path is trusted: a key built
    from a tar path is a path traversal unless it is checked (repo_path).
    Symlinks, hardlinks and devices are skipped outright -- a link's target is
    exactly the thing a hostile archive would aim somewhere else.
    """
    kept, total = {}, 0
    with tarfile.open(fileobj=fileobj, mode="r|gz") as tar:
        for member in tar:
            if not member.isreg():
                continue
            path = repo_path(member.name)
            if path is None or SKIP_DIRS & set(path.split("/")):
                continue
            if not _suffix_could_match(path):
                continue
            data = tar.extractfile(member).read()
            if not is_snapshot_file(path, data):
                continue
            total += len(data)
            if len(kept) >= MAX_SNAPSHOT_FILES:
                raise TooLarge(f"more than {MAX_SNAPSHOT_FILES} IaC files")
            if total > MAX_SNAPSHOT_BYTES:
                raise TooLarge(f"IaC files total over {MAX_SNAPSHOT_BYTES // (1024 * 1024)}MB")
            kept[path] = data
    return kept


def repo_path(member_name):
    """The path inside the repository, or None if the name is unsafe.

    GitHub's tarballs put everything under one `<owner>-<repo>-<sha>/`
    directory, which is stripped. Anything absolute, with a `..` or `.`
    component, an empty component or a backslash is refused rather than
    normalised: normalising a hostile name is how traversal gets through.
    """
    if member_name.startswith("/") or "\\" in member_name:
        return None
    parts = member_name.split("/")
    if len(parts) < 2:
        return None
    rest = parts[1:]
    if any(p in ("", ".", "..") for p in rest):
        return None
    return "/".join(rest)


def _suffix_could_match(path):
    name = posixpath.basename(path)
    return name.endswith(SNAPSHOT_SUFFIXES) or name.endswith((".json", ".template"))


def is_snapshot_file(path, data):
    """Whether the scanner would open this file -- scripts/scan.py's
    is_snapshot_file, on bytes rather than a path on disk."""
    name = posixpath.basename(path)
    if name.endswith(SNAPSHOT_SUFFIXES):
        return True
    if not name.endswith((".json", ".template")):
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(ARM_SCHEMA_RE.search(text) or CFN_MARKER_RE.search(text))


def replace_snapshot(pr_id, kept):
    """Make scans/<pr_id>/ exactly `kept` -- scan.py's upload, from memory.
    A file the PR deletes must stop being scanned, so stale keys go too."""
    prefix = f"scans/{pr_id}/"
    existing = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=ARTIFACTS_BUCKET, Prefix=prefix):
        existing.update(o["Key"] for o in page.get("Contents", []))
    wanted = {prefix + path: data for path, data in kept.items()}
    for key, data in wanted.items():
        s3.put_object(Bucket=ARTIFACTS_BUCKET, Key=key, Body=data)
    removed = sorted(existing - set(wanted))
    for chunk in (removed[i:i + 1000] for i in range(0, len(removed), 1000)):
        s3.delete_objects(Bucket=ARTIFACTS_BUCKET, Delete={"Objects": [{"Key": k} for k in chunk]})


# ======================================================================
# select_files
# ======================================================================

def select_files(event):
    """The Remediate Map's items on a GitHub run: changed files with a finding
    still "mapped", or with a stale fix. Not mapping-agent's `files`, which
    lists only what that pass mapped -- on a Draft fixes run every finding was
    mapped by the push before it, so that list is empty and nothing would be
    remediated.

    A stale fix was drafted on a version of the file the PR has since moved
    past. remediation-agent reopens and redrafts it, but only on a file it is
    asked about, and before this a file whose only problem was a stale fix
    was never asked about: the hold message said "run Draft fixes again" and
    the run did nothing (write-back-spec §8)."""
    pr_id = event["pr_id"]
    changed = set(event.get("changed_files") or [])
    on_changed = [f for f in query_findings(pr_id)
                  if f["file"] in changed and not f.get("no_longer_detected")]
    mapped = {f["file"] for f in on_changed if f.get("status") == "mapped"}
    files = sorted(mapped | stale_files(pr_id, [f for f in on_changed if f["file"] not in mapped]))
    carried = event.get("map") or {}
    return {**carried, "files": files, "remaining": 0}


def stale_files(pr_id, findings):
    """The files among `findings` holding a fix remediation-agent would
    reopen as stale: one read of the snapshot per file with a fix on it."""
    by_file = {}
    for f in findings:
        if f.get("status") in ("fix-proposed", "resolved"):
            by_file.setdefault(f["file"], []).append(f)
    stale = set()
    for path, fixes in by_file.items():
        try:
            snapshot_sha256 = _content_sha256(_s3_text(f"scans/{pr_id}/{path}"))
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchKey":
                raise
            continue  # the PR deleted the file; nothing to redraft on
        if any(_stale_reason(f, snapshot_sha256) for f in fixes):
            stale.add(path)
    return stale


def _stale_reason(finding, snapshot_sha256):
    """Why this finding's fix can no longer land or be built on, or None.

    Must stay identical to remediation-agent's copy, which decides what a
    Draft fixes run reopens (corpus/test_corpus.py). A drift here offers the
    button for a file the run then leaves alone, or never offers it.
    """
    fix = finding.get("proposed_fix") or {}
    if (finding.get("status") not in ("fix-proposed", "resolved") or not fix.get("diff")
            or fix.get("committed") or finding.get("no_longer_detected")):
        return None
    if not fix.get("base_sha256"):
        return "it was drafted before fixes recorded the file they were drafted on"
    if fix["base_sha256"] != snapshot_sha256:
        return "the file has changed since it was drafted"
    return None


def query_findings(pr_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    kwargs = {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :sk)",
        "ExpressionAttributeValues": {":pk": f"PR#{pr_id}", ":sk": "FINDING#"},
    }
    items = []
    while True:
        response = table.query(**kwargs)
        items.extend(response.get("Items", []))
        if not response.get("LastEvaluatedKey"):
            return items
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]


# ======================================================================
# report
# ======================================================================

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
ANNOTATION_LEVEL = {"CRITICAL": "failure", "HIGH": "failure", "MEDIUM": "warning"}


def report(event):
    state = event["state"]
    github = state["github"]
    pr_id = state["pr_id"]
    fetched = state["fetch"]
    trigger = github.get("trigger", "push")
    remediate = bool(state.get("remediate"))
    execution_name = event["execution_name"]
    repo = github["repository"]
    token = installation_token(github, {"checks": "write", "pull_requests": "write", "metadata": "read"})
    check_path = f"/repos/{repo}/check-runs/{int(fetched['check_run_id'])}"

    if fetched.get("status") != "ok":
        _complete(check_path, token, "Not scanned", fetched.get("reason") or "Nothing to scan.")
        return {"status": fetched.get("status")}

    # Every finding the scan still reports. Not only the open ones: a
    # "superseded" finding is covered by another finding's fix, which is a
    # statement about the fix, not the code -- until the fix is applied the
    # misconfiguration is still on the line. Leaving them out dropped six of
    # eighteen annotations from PugetScope #10 once Draft fixes had run.
    findings = [f for f in query_findings(pr_id) if not f.get("no_longer_detected")]
    pr_files = json.loads(s3.get_object(
        Bucket=ARTIFACTS_BUCKET, Key=files_key(pr_id, github["head_sha"]))["Body"].read())
    added, visible = diff_lines(pr_files)

    on_added = [f for f in findings if _lines(f) & added.get(f["file"], set())]
    annotations = [annotation(f) for f in sorted(on_added, key=_sort_key)]

    posted, held = [], []
    offer = []
    changed = set(fetched.get("changed_files") or [])
    if remediate:
        posted, held = post_suggestions(github, pr_id, execution_name, findings, visible, token)
        offer = plan_offer(pr_id, [f for f in findings if f["file"] in changed])

    on_changed = [f for f in findings if f["file"] in changed]
    # The same test select_files makes, so the button is offered exactly when
    # the run it starts has something to do. Stale fixes are only looked for
    # when nothing is mapped: each is a snapshot read.
    offer_fixes = (not remediate) and (
        any(f.get("status") == "mapped" for f in on_changed)
        or bool(stale_files(pr_id, on_changed)))

    title = (f"{len(on_added)} finding(s) on lines this PR adds" if on_added
             else "No findings on lines this PR adds")
    # Commit fixes is offered once write-back is deployed and the offer has
    # a file in it; the click commits the stored offer (spec §3.1).
    commit_button = bool(offer) and COMMIT_FIXES_ENABLED
    summary = build_summary(
        state=state, findings=findings, on_added=on_added, posted=posted, held=held,
        remediate=remediate, offer_fixes=offer_fixes, trigger=trigger, offer=offer,
        commit_button=commit_button,
    )
    actions = ([{"label": "Draft fixes", "description": "Draft and self-check fixes",
                 "identifier": DRAFT_FIXES_ACTION}] if offer_fixes else [])
    if commit_button:
        # GitHub's limits: label 20 characters, description 40 (verify).
        actions.append({"label": "Commit fixes", "description": "Commit the verified fixes listed below",
                        "identifier": COMMIT_FIXES_ACTION})

    batches = [annotations[i:i + ANNOTATIONS_PER_REQUEST]
               for i in range(0, len(annotations), ANNOTATIONS_PER_REQUEST)] or [[]]
    # Annotations accumulate across updates; the run completes on the last one
    # so a reader never sees "completed" with half of them missing.
    for batch in batches[:-1]:
        _request("PATCH", check_path, token, {
            "output": {"title": title, "summary": summary, "annotations": batch}})
    _complete(check_path, token, title, summary, annotations=batches[-1], actions=actions)

    suggestion_count = sum(len(p["hunks"]) for p in posted)
    _emit_metrics(
        {"AnnotationsPosted": len(annotations), "SuggestionsPosted": suggestion_count,
         "FilesHeldFromSuggestions": len(held)},
        {"Environment": ENVIRONMENT},
        pr_id=pr_id, execution=execution_name, trigger=trigger,
    )
    result = {"annotations": len(annotations), "suggestions": suggestion_count,
              "files_posted": len(posted), "files_held": len(held)}
    if offer:
        # Stored by the state machine after this state (RecordOffer), keyed
        # by the check run: what a Commit fixes click on it commits. Tips
        # and hashes only -- the diffs are in the summary, and the state is
        # capped at 256KB.
        result["offer"] = {
            "check_run_id": int(fetched["check_run_id"]),
            "head_sha": github["head_sha"],
            "files": [{k: o[k] for k in ("file", "tip", "chain", "content_sha256")}
                      for o in offer],
        }
    return result


def _complete(check_path, token, title, summary, annotations=(), actions=()):
    output = {"title": title[:255], "summary": summary[:65000]}
    if annotations:
        output["annotations"] = list(annotations)
    _request("PATCH", check_path, token, {
        "status": "completed",
        # Advisory in v3 whatever it found (spec D1): a check that blocks
        # merges should wait for a fix-acceptance rate that says it deserves to.
        "conclusion": "neutral",
        "output": output,
        **({"actions": list(actions)} if actions else {}),
    })


def _span(finding):
    """(start, end) as ints, or None for a finding about the whole file.

    Some rules have no line: Trivy's KSV-0117 on a Kubernetes manifest came
    back as [None, None] on the first PugetScope run, and report died on it.
    Such a finding is counted in the summary but never annotated -- it cannot
    be placed on a line the PR added.
    """
    line_range = finding.get("line_range") or []
    if len(line_range) != 2 or None in line_range:
        return None
    try:
        return int(line_range[0]), int(line_range[1])
    except (TypeError, ValueError):
        return None


def _lines(finding):
    span = _span(finding)
    return set(range(span[0], span[1] + 1)) if span else set()


def _sort_key(finding):
    severity = str(finding.get("severity", "UNKNOWN")).upper()
    rank = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return (rank, finding["file"], (_span(finding) or (0, 0))[0])


def diff_lines(pr_files):
    """Per file, the right-side lines the PR adds, and every right-side line
    its diff shows (added plus context) -- the lines a review comment may
    attach to."""
    added, visible = {}, {}
    for f in pr_files:
        patch = f.get("patch")
        if not patch or f.get("status") == "removed":
            continue
        a, v = added.setdefault(f["filename"], set()), visible.setdefault(f["filename"], set())
        line = 0
        for text in patch.split("\n"):
            header = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", text)
            if header:
                line = int(header.group(1))
                continue
            if text.startswith("+"):
                a.add(line)
                v.add(line)
                line += 1
            elif text.startswith(" "):
                v.add(line)
                line += 1
            # "-" lines are left-side only; "\ No newline" moves nothing.
    return added, visible


def annotation(finding):
    # Only called for findings on added lines, which have a span.
    start, end = _span(finding)
    severity = str(finding.get("severity", "UNKNOWN")).upper()
    controls = sorted({m.get("control_id") for m in finding.get("control_mappings") or []
                       if m.get("control_id")})
    message = f"{finding.get('title') or finding['rule_id']}\n\n{finding['source']} rule {finding['rule_id']}"
    if finding.get("resource"):
        message += f" on {finding['resource']}"
    if controls:
        message += f". Controls: {', '.join(controls)}"
    return {
        "path": finding["file"],
        "start_line": start,
        "end_line": end,
        "annotation_level": ANNOTATION_LEVEL.get(severity, "notice"),
        # checkov reports no severity; "(unknown)" on half the annotations
        # said nothing a reader could use.
        "title": (finding["rule_id"] if severity == "UNKNOWN"
                  else f"{finding['rule_id']} ({severity.lower()})")[:255],
        "message": message[:60000],
    }


def build_summary(*, state, findings, on_added, posted, held, remediate, offer_fixes, trigger,
                  offer=(), commit_button=False):
    github = state["github"]
    lines = [
        f"**{len(on_added)}** finding(s) on lines this PR adds, of **{len(findings)}** "
        f"in the repository at `{github['head_sha'][:7]}` "
        f"({state['fetch'].get('kept_count', 0)} IaC file(s) scanned).",
        "",
    ]
    by_severity = {}
    for f in findings:
        by_severity[str(f.get("severity", "UNKNOWN")).upper()] = by_severity.get(
            str(f.get("severity", "UNKNOWN")).upper(), 0) + 1
    if findings:
        lines += ["| Severity | In repository | On added lines |", "|---|---:|---:|"]
        for severity in sorted(by_severity, key=lambda s: SEVERITY_ORDER.index(s)
                               if s in SEVERITY_ORDER else 99):
            here = sum(1 for f in on_added if str(f.get("severity", "UNKNOWN")).upper() == severity)
            lines.append(f"| {severity} | {by_severity[severity]} | {here} |")
        lines.append("")

    scan_errors = (state.get("scan") or {}).get("scan_errors") or []
    if scan_errors:
        lines += [f"**{len(scan_errors)} file(s) could not be parsed** and were not scanned; "
                  "the dashboard lists them.", ""]

    if remediate:
        count = sum(len(p["hunks"]) for p in posted)
        if posted:
            lines.append(f"Posted **{count}** suggested change(s) across {len(posted)} file(s). "
                         "Each file's suggestions were self-checked together as one change: "
                         "apply all of a file's suggestions, or none.")
        elif not held:
            lines.append("No fix passed its self-check on the files this PR changes.")
        for p in posted:
            if p.get("left_out"):
                rules = ", ".join(f"`{r}`" for r in p["left_out"])
                lines.append(f"- `{p['file']}`: {rules} not posted -- drafted on top of a fix "
                             "held for review, so the suggestion would carry the held change")
        for h in held:
            lines.append(f"- `{h['file']}`: fix not posted -- {h['reason']}")
        lines.append("")
        lines += offer_section(offer, button=commit_button)
    elif offer_fixes:
        lines += ["**Draft fixes** (above) drafts and self-checks a fix for each mapped finding "
                  "in the files this PR changes, redrafts any fix whose file has changed since "
                  "it was drafted, and posts the ones that verify as suggestions. "
                  "It makes model calls, so it waits to be asked.", ""]

    lines.append("Findings on added lines approximate \"introduced by this PR\": a change that "
                 "enables a finding on a line it did not touch is counted in the repository "
                 "total but not annotated.")
    if DASHBOARD_URL:
        lines += ["", f"Review every finding, control mapping and fix in the "
                      f"[dashboard]({DASHBOARD_URL}/prs/{state['pr_id']})."]
    return "\n".join(lines)


# ---------- the offer (github-first-review-spec §3.1) ----------

# The offer's diffs share the summary's 65,535 characters with everything
# else in it; past this, the files are listed without them.
OFFER_DIFF_BUDGET = 40000


def plan_offer(pr_id, findings):
    """Per file, the verified fixes a Commit fixes click would commit.

    The same chain v3 posts as suggestions -- chain_tip over the file's
    verified fixes -- but not bound to the PR's diff lines: a summary can
    show a fix a suggestion cannot. Approved fixes count as well as proposed
    ones, since an approval does not unverify anything; a committed one does
    not. A file is offered only if its tip was drafted on the head as it is
    now, which is what the committer will check again at the click.
    """
    by_file = {}
    for f in findings:
        fix = f.get("proposed_fix") or {}
        if (f.get("status") in ("fix-proposed", "resolved") and fix.get("self_check_passed")
                and fix.get("diff") and not fix.get("committed")
                and not f.get("no_longer_detected")):
            by_file.setdefault(f["file"], {})[f["finding_id"]] = f

    offer = []
    for path in sorted(by_file):
        fixes = by_file[path]
        tip = chain_tip(fixes)
        if tip is None:
            continue
        try:
            head = _s3_text(f"scans/{pr_id}/{path}")
            corrected = _s3_text(f"fixes/{pr_id}/{tip['finding_id']}/{path}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchKey":
                raise
            continue
        base = tip["proposed_fix"].get("base_sha256")
        if not base or base != _content_sha256(head) or _content_sha256(corrected) == base:
            continue
        chain = [a["finding_id"] for a in tip["proposed_fix"].get("applies_after") or []]
        chain.append(tip["finding_id"])
        offer.append({
            "file": path,
            "tip": tip["finding_id"],
            "chain": chain,
            "rules": sorted({fixes[i]["rule_id"] for i in chain}),
            "content_sha256": _content_sha256(corrected),
            "diff": "".join(difflib.unified_diff(
                head.splitlines(keepends=True), corrected.splitlines(keepends=True),
                fromfile=f"a/{path}", tofile=f"b/{path}")),
        })
    return offer


def offer_section(offer, button=False):
    """The summary's account of the offer: what can be committed, file by
    file, with the change each makes -- in or out of the PR's diff, which a
    suggestion cannot be. Code-produced: rule ids, paths and diffs of
    verified fixes, no model prose. Paths are the repository's, so they are
    escaped where they sit inside HTML."""
    if not offer:
        return []
    if button:
        lead = (f"**Commit fixes** (above) commits the verified fixes below to this branch as "
                f"one commit, {len(offer)} file(s), as the CascadeSec Fixes app. It needs write "
                "access to the repository. Each file is checked against the branch again first, "
                "and a file that has changed since is held. The suggestions above cover what "
                "GitHub can show inline; this covers every verified file.")
    else:
        lead = (f"**Ready to commit:** the verified fixes below, {len(offer)} file(s), including "
                "any GitHub cannot show as a suggestion. Approve them in the dashboard to commit "
                "them together.")
    lines = [lead, ""]
    budget = OFFER_DIFF_BUDGET
    shown = []
    for o in offer:
        block = f"```diff\n{o['diff'].rstrip()}\n```"
        if len(block) > budget:
            break
        budget -= len(block)
        shown.append(o["file"])
        rules = ", ".join(f"`{r}`" for r in o["rules"])
        lines += [f"<details><summary><code>{html.escape(o['file'])}</code>: {rules}</summary>",
                  "", block,
                  "", "</details>", ""]
    for o in offer:
        if o["file"] not in shown:
            lines.append(f"- `{o['file']}`: {', '.join(f'`{r}`' for r in o['rules'])} "
                         "(the change is too large to show here; see the dashboard)")
    if len(shown) < len(offer):
        lines.append("")
    return lines


# ---------- suggestions ----------

def post_suggestions(github, pr_id, execution_name, findings, visible, token):
    """One review holding every postable file's verified fix, as suggestions.

    Per file, not per finding. Fixes are chained -- each drafted on the file
    as the previous verified fix left it -- so one fix's diff is in the line
    numbers of an intermediate file nobody has, and only the chain's last
    corrected file was self-checked with every earlier fix in it. So the
    suggestion is that file diffed against the PR head, and a file posts all
    of its hunks or none: a subset was never verified.
    """
    marker = f"<!-- cascadesec:{execution_name} -->"
    repo, number = github["repository"], int(github["pr_number"])
    for review in _paginate(f"/repos/{repo}/pulls/{number}/reviews", token):
        if marker in (review.get("body") or ""):
            logger.info("review for %s already posted", execution_name)
            return [], []

    posted, held = [], []
    by_file = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    for path in sorted(visible):
        plan = plan_file(pr_id, path, by_file.get(path, []), visible[path])
        if plan is None:
            continue
        (posted if "hunks" in plan else held).append(plan)

    if not posted:
        return posted, held

    comments = [c for p in posted for c in p["comments"]]
    body = (f"{marker}\n**CascadeSec** drafted fixes for findings in this PR and verified each "
            "file's fixes by re-scanning the corrected file. Suggestions in one file were "
            "verified together: apply all of them (**Add suggestion to batch**, then commit) "
            "or none.")
    try:
        _request("POST", f"/repos/{repo}/pulls/{number}/reviews", token, {
            "commit_id": github["head_sha"], "event": "COMMENT", "body": body, "comments": comments,
        })
    except GitHubError as e:
        if e.status != 422:
            raise
        # GitHub refuses the whole review if any comment's lines are outside
        # the diff. plan_file checks for that, so this means the check and
        # GitHub disagree -- report it rather than fail the execution.
        logger.error("review rejected: %s", e)
        held.extend({"file": p["file"], "reason": "GitHub rejected the suggestion"} for p in posted)
        return [], held
    return posted, held


def plan_file(pr_id, path, file_findings, visible_lines):
    """The suggestions for one file, or why there are none (None if the file
    has no verified fix at all)."""
    fixes = {f["finding_id"]: f for f in file_findings
             if f.get("status") == "fix-proposed"
             and (f.get("proposed_fix") or {}).get("self_check_passed")
             and (f.get("proposed_fix") or {}).get("diff")}
    if not fixes:
        return None

    tip = chain_tip(fixes)
    if tip is None:
        return {"file": path, "reason": "every verified fix was drafted on top of one held for "
                                        "review; see the dashboard"}

    head = _s3_text(f"scans/{pr_id}/{path}")
    chain = [a["finding_id"] for a in tip["proposed_fix"].get("applies_after") or []] + [tip["finding_id"]]
    # The suggestion is the tip's whole corrected file diffed against head,
    # so head must be exactly the file the chain was drafted on. Checking
    # that the root's diff still applies was not enough: on
    # cascadesec-testbed #3 it applied to a head with a resource appended
    # below it, and the suggestion deleted the resource (write-back-spec §8).
    base = tip["proposed_fix"].get("base_sha256")
    if not base:
        return {"file": path, "reason": "drafted before fixes recorded their base; "
                                        "run Draft fixes again"}
    if base != _content_sha256(head):
        return {"file": path, "reason": "the file has changed since this fix was drafted; "
                                        "run Draft fixes again"}

    corrected = _s3_text(f"fixes/{pr_id}/{tip['finding_id']}/{path}")
    hunks = suggestion_hunks(head, corrected)
    if not hunks:
        return None
    outside = [h for h in hunks if not set(range(h["start"], h["end"] + 1)) <= visible_lines]
    if outside:
        return {"file": path, "reason": "the fix changes lines outside this PR's diff, which "
                                        "GitHub cannot take as a suggestion; see the dashboard"}

    rules = ", ".join(sorted({f"`{fixes[i]['rule_id']}`" for i in chain}))
    comments = []
    for n, h in enumerate(hunks, 1):
        comment = {"path": path, "side": "RIGHT", "line": h["end"],
                   "body": (f"**CascadeSec** fix, part {n} of {len(hunks)} for `{path}` "
                            f"(verified together: {rules}).\n\n{_suggestion_block(h['text'])}")}
        if h["start"] != h["end"]:
            comment.update(start_line=h["start"], start_side="RIGHT")
        comments.append(comment)
    left_out = sorted(fixes[i]["rule_id"] for i in set(fixes) - set(chain))
    return {"file": path, "hunks": hunks, "comments": comments, "chain": chain,
            "left_out": left_out}


def chain_tip(fixes):
    """The end of the longest chain made only of verified fixes, or None.

    `fixes` is the file's fix-proposed, self-checked fixes. A chain is valid
    if every link is one of them and unchanged since the chain was built
    (applies_after records each link's diff hash). remediation-agent drafts
    on top of held fixes too -- a fix held for an assumption still cleared
    its finding, so the next is drafted on it -- and such a fix's corrected
    file contains the held change. Its chain has a link outside `fixes`, so
    it is not valid, and posting it would have slipped an unreviewed change
    into a suggestion. The longest valid chain is safe to post whole: its tip
    was self-checked with every earlier link applied.

    *Was: the tip had to cover every verified fix, or nothing was posted.*
    On cascadesec-testbed #2 that held back KMS rotation and database
    encryption because a later fix on the same file was built on a held one.
    Verified fixes the tip does not cover are now reported as left out.
    """
    def valid(fix):
        for link in fix["proposed_fix"].get("applies_after") or []:
            prior = fixes.get(link["finding_id"])
            if prior is None or _sha256(prior["proposed_fix"]["diff"]) != link["diff_sha256"]:
                return False
        return True

    candidates = [f for f in fixes.values() if valid(f)]
    if not candidates:
        return None
    return max(candidates, key=lambda f: (len(f["proposed_fix"].get("applies_after") or []),
                                          f["finding_id"]))


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _content_sha256(content):
    """Must stay identical to remediation-agent's helper of the same name,
    which records the hash of the file a chain was drafted on."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def suggestion_hunks(head, corrected):
    """Replacements in head's line numbers: [{start, end, text}], 1-based and
    inclusive. A pure insertion has no head lines to attach to, so it is
    anchored to the line before it (or after, at the top of the file) and that
    line is repeated in the suggestion."""
    # splitlines: a trailing newline is not a line, and a suggestion cannot
    # add or remove one -- so a difference only there is no difference.
    old, new = head.splitlines(), corrected.splitlines()
    hunks = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        replacement = new[j1:j2]
        if i1 == i2:
            if i1 > 0:
                i1, replacement = i1 - 1, [old[i1 - 1]] + replacement
            elif old:
                i2, replacement = i2 + 1, replacement + [old[0]]
            else:
                continue  # an empty file has no line to attach anything to
        hunks.append({"start": i1 + 1, "end": i2, "text": "\n".join(replacement)})
    return hunks


def _suggestion_block(text):
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}suggestion\n{text}\n{fence}"


def _s3_text(key):
    return s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=key)["Body"].read().decode("utf-8")


# ======================================================================
# report_commit (github-first-review-spec §3.6)
# ======================================================================

# Not CHECK_NAME: webhook-receiver takes a check run named that as ours,
# with buttons, and this one has none.
COMMIT_CHECK_NAME = "CascadeSec fixes"


def report_commit(event):
    """Say on the PR what a Commit fixes click did: a check run of its own,
    on the new commit if there is one, otherwise on the commit the offer
    was for. The writer App cannot post a check run -- it holds Contents
    write and nothing else -- so the commit state machine brings the
    committer's answer here.

    Code-produced only: the outcome per file, the commit, and the login
    that clicked (not an @-mention, which would notify them).
    """
    github, outcome = event["github"], event.get("commit") or {}
    repo = github["repository"]
    login = (str(outcome.get("requested_by") or "").removeprefix("github:")
             or (event.get("sender") or {}).get("login", "someone"))
    status = outcome.get("status") or "failed"
    commit_sha = outcome.get("commit_sha")
    files = outcome.get("files") or []
    committed = [f for f in files if f.get("outcome") == "committed"]

    if status == "committed" and commit_sha:
        title = f"Committed {len(committed)} file(s) of verified fixes"
        lines = [f"Committed in `{commit_sha[:7]}` by the CascadeSec Fixes app, after {login} "
                 "clicked **Commit fixes**. The scan of that commit is the fixes' check on the "
                 "branch."]
    elif status == "committed":
        title = "The offered fixes are already on the branch"
        lines = ["Nothing new was committed: the branch already has the offered fixes."]
    elif status == "failed":
        title = "Commit fixes did not finish"
        lines = [f"The commit did not finish: {outcome.get('reason') or 'unknown error'}."]
    else:
        title = "Commit fixes committed nothing"
        lines = [f"Nothing was committed: {outcome.get('reason') or 'see each file'}."]
    if files:
        lines += ["", "| File | Outcome |", "|---|---|"]
        for f in files:
            said = f.get("outcome") if not f.get("reason") else f"{f.get('outcome')}: {f['reason']}"
            lines.append(f"| `{_cell(f.get('file'))}` | {_cell(said)} |")
    if DASHBOARD_URL:
        lines += ["", f"The request and each fix's audit trail are in the "
                      f"[dashboard]({DASHBOARD_URL}/prs/{event['pr_id']})."]

    token = installation_token(github, {"checks": "write", "metadata": "read"})
    _request("POST", f"/repos/{repo}/check-runs", token, {
        "name": COMMIT_CHECK_NAME,
        "head_sha": commit_sha or github["head_sha"],
        "status": "completed",
        # Success means the commit landed; anything else is information,
        # not a failure of the PR, as the scan's own check is neutral (D1).
        "conclusion": "success" if status == "committed" else "neutral",
        **({"details_url": f"{DASHBOARD_URL}/prs/{event['pr_id']}"} if DASHBOARD_URL else {}),
        "output": {"title": title[:255], "summary": "\n".join(lines)[:65000]},
    })
    _emit_metrics({"CommitOutcomesReported": 1}, {"Environment": ENVIRONMENT},
                  pr_id=event["pr_id"], status=status)
    return {"reported": status}


def _cell(text):
    """Text for one markdown table cell: a path or a reason may hold a pipe
    or a line break, and either would break the table."""
    return str(text).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


# ======================================================================
# The failure backstop (EventBridge)
# ======================================================================

def on_execution_failed(event):
    """Complete the check run of an execution that ended badly.

    Found by external_id (the execution name, set by fetch), because the
    event carries the execution's input but not its state. If fetch never
    created one, a completed run is created, so the failure is still visible
    on the PR instead of absent.
    """
    detail = event.get("detail") or {}
    try:
        execution_input = json.loads(detail.get("input") or "{}")
    except ValueError:
        execution_input = {}
    github = execution_input.get("github")
    if not github:
        return {"skipped": "not a GitHub execution"}

    name, status = detail.get("name", ""), detail.get("status", "FAILED")
    token = installation_token(github, {"checks": "write", "metadata": "read"})
    repo, sha = github["repository"], github["head_sha"]
    runs = _request("GET", f"/repos/{repo}/commits/{sha}/check-runs?check_name={CHECK_NAME}&filter=all",
                    token)["check_runs"]
    ours = [r for r in runs if r.get("external_id") == name]
    summary = (f"The pipeline execution `{name}` ended with **{status}** before it could "
               "report. Nothing was posted. Push again, or use **Re-run**, to retry.")
    if ours:
        for run in ours:
            if run.get("status") != "completed":
                _complete(f"/repos/{repo}/check-runs/{run['id']}", token, "Scan did not finish", summary)
    else:
        _request("POST", f"/repos/{repo}/check-runs", token, {
            "name": CHECK_NAME, "head_sha": sha, "external_id": name,
            "status": "completed", "conclusion": "neutral",
            "output": {"title": "Scan did not finish", "summary": summary},
        })
    _emit_metrics({"ExecutionsReportedFailed": 1}, {"Environment": ENVIRONMENT},
                  execution=name, status=status)
    return {"completed": len(ours) or 1}


def _emit_metrics(metrics, dimensions, **context):
    """One Embedded Metric Format line; see review-api's _emit_metrics."""
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
