"""webhook-receiver Lambda (docs/ci-integration-spec.md §3).

The GitHub App's webhook endpoint: verify a delivery's signature, decide
whether it is an event worth acting on -- a PR opened or pushed to, or a
click on our check run's Draft fixes or Re-run -- and start one pipeline
execution for it. Nothing else -- it never calls GitHub, never touches S3,
and cannot read the App's private key (terraform/iam.tf). A request that got
past it could start an execution and nothing more.

Wired to POST /github/webhook on the review API (payload format 2.0), the one
route with no JWT authorizer. Its authentication is the HMAC below, which is
checked against the raw body before a byte of it is parsed.

Responses, all of which GitHub records on the delivery (the App's Advanced
tab):
  202  execution started
  200  ping, or a redelivery of something already started
  204  authentic, but not an event that is scanned
  400  authentic, but not a payload this function understands
  401  signature missing or wrong
  503  the webhook secret has no value yet -- fails closed (secrets.tf)
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

WEBHOOK_SECRET_ARN = os.environ.get("WEBHOOK_SECRET_ARN")
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN")

secretsmanager = boto3.client("secretsmanager")
sfn = boto3.client("stepfunctions")

# Actions that mean "the head of this PR is new, or newly worth scanning".
# ready_for_review is here because a draft is skipped when opened (spec §3,
# D4); closed, edited, labeled and the rest change no file.
SCANNED_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}

# The check run github-gateway creates, and its one button (spec §5). Must
# match github-gateway's CHECK_NAME and DRAFT_FIXES_ACTION.
CHECK_NAME = "CascadeSec"
DRAFT_FIXES_ACTION = "draft_fixes"
# requested_action is the Draft fixes button; rerequested is GitHub's own
# Re-run on the check.
CHECK_RUN_ACTIONS = {"requested_action", "rerequested"}

# Long enough that a secret rotated with put-secret-value is picked up within
# minutes; short enough that a burst of forged requests is not a burst of
# Secrets Manager reads. A failed signature never refetches, for the same
# reason.
SECRET_TTL_SECONDS = 300
_secret_cache = {"value": None, "fetched_at": 0.0}


class SecretUnavailable(Exception):
    """The webhook secret cannot be read, so no signature can be checked."""


def handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    delivery = headers.get("x-github-delivery", "-")
    gh_event = headers.get("x-github-event", "")

    body = _raw_body(event)

    try:
        secret = _webhook_secret()
    except SecretUnavailable as e:
        logger.error("delivery %s: webhook secret unavailable: %s", delivery, e)
        return _response(503, "webhook secret not configured")

    if not verify_signature(secret, body, headers.get("x-hub-signature-256")):
        logger.warning("delivery %s: signature rejected (event %r)", delivery, gh_event)
        return _response(401, "bad signature")

    # Authentic from here on. Parsing starts only now.
    try:
        payload = json.loads(body)
    except ValueError:
        return _response(400, "body is not JSON")

    if gh_event == "ping":
        logger.info("delivery %s: ping, hook %s", delivery, payload.get("hook_id"))
        return _response(200, "pong")

    action = payload.get("action")
    if gh_event == "pull_request":
        pr = payload.get("pull_request") or {}
        if action not in SCANNED_ACTIONS:
            logger.info("delivery %s: ignored pull_request.%s", delivery, action)
            return _response(204)
        if pr.get("draft"):
            logger.info("delivery %s: draft PR, not scanned until ready_for_review", delivery)
            return _response(204)
    elif gh_event == "check_run" and action in CHECK_RUN_ACTIONS:
        check_run = payload.get("check_run") or {}
        # GitHub sends every check run on the repository -- CI's included --
        # to an App subscribed to check_run. Only ours carries a button.
        if check_run.get("name") != CHECK_NAME:
            return _response(204)
        if action == "requested_action" and \
                (payload.get("requested_action") or {}).get("identifier") != DRAFT_FIXES_ACTION:
            return _response(204)
        if not check_run.get("pull_requests"):
            # GitHub leaves this empty for a PR from a fork. Without the PR
            # there is no number to scan; the push that opened it already ran.
            logger.info("delivery %s: check_run with no pull request (a fork?)", delivery)
            return _response(204)
    elif gh_event == "check_suite" and action == "rerequested":
        # The PR page's Re-run re-runs the App's whole suite, and arrives as
        # this rather than check_run.rerequested (found on PugetScope #10,
        # 2026-09-25). GitHub sends it only to the App that owns the suite,
        # so there is no name to check -- it is ours by construction.
        if not (payload.get("check_suite") or {}).get("pull_requests"):
            logger.info("delivery %s: check_suite with no pull request (a fork?)", delivery)
            return _response(204)
    else:
        logger.info("delivery %s: ignored %s.%s", delivery, gh_event, action)
        return _response(204)

    try:
        execution_input = (build_input(payload) if gh_event == "pull_request"
                           else build_check_run_input(payload, delivery))
    except (KeyError, TypeError, ValueError, IndexError) as e:
        logger.error("delivery %s: malformed %s payload: %s", delivery, gh_event, e)
        return _response(400, f"malformed {gh_event} payload")

    github = execution_input["github"]
    name = execution_name(execution_input["pr_id"], github["head_sha"], github["trigger"])
    try:
        sfn.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=name,
            input=json.dumps(execution_input, sort_keys=True),
        )
    except sfn.exceptions.ExecutionAlreadyExists:
        # A redelivery, or a second event (reopened, ready_for_review) for a
        # head that was already scanned. The name is what makes this free.
        logger.info("delivery %s: execution %s already exists", delivery, name)
        return _response(200, "already started")

    logger.info("delivery %s: %s.%s -> execution %s", delivery, gh_event, action, name)
    return _response(202, "started")


def _raw_body(event):
    """The request body as the bytes GitHub signed.

    HTTP API hands the body over as a string, base64-encoded when it is not
    text. The signature is over bytes, so this decodes and never
    re-serialises: json.dumps(json.loads(body)) is not the same bytes, and a
    check against it would reject every real delivery.
    """
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        return base64.b64decode(body)
    return body.encode("utf-8")


def verify_signature(secret, body, header):
    """Whether `header` is GitHub's X-Hub-Signature-256 for `body`.

    compare_digest, not ==: an == comparison stops at the first differing
    byte, and how long it takes says how many leading bytes were right.
    """
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.encode("ascii"), header.encode("ascii", "replace"))


def _webhook_secret():
    now = time.monotonic()
    cached = _secret_cache["value"]
    if cached is not None and now - _secret_cache["fetched_at"] < SECRET_TTL_SECONDS:
        return cached
    try:
        value = secretsmanager.get_secret_value(SecretId=WEBHOOK_SECRET_ARN)["SecretString"]
    except secretsmanager.exceptions.ResourceNotFoundException as e:
        # The secret exists but has no version: put-secret-value has not been
        # run yet. Deliberately not a placeholder -- see secrets.tf.
        raise SecretUnavailable("no value set") from e
    value = value.strip()
    if not value:
        raise SecretUnavailable("value is empty")
    _secret_cache.update(value=value, fetched_at=now)
    return value


def build_input(payload):
    """The execution input for a pull_request event.

    Deterministic in the payload: GitHub redelivers the same body, and a
    Standard execution started twice under one name with different input is
    rejected differently from one with the same input. So nothing here is a
    timestamp or the delivery id; those go to the log.
    """
    pr = payload["pull_request"]
    repo = payload["repository"]
    pr_id = make_pr_id(repo["id"], pr["number"])
    return {
        "pr_id": pr_id,
        "s3_prefix": f"scans/{pr_id}/",
        # A push scans and maps; drafting fixes waits for a maintainer to ask
        # (spec §5), because it is the stage that costs model calls.
        "remediate": False,
        "github": {
            "installation_id": int(payload["installation"]["id"]),
            "repository_id": int(repo["id"]),
            "repository": repo["full_name"],
            "pr_number": int(pr["number"]),
            "head_sha": _sha(pr["head"]["sha"]),
            "base_sha": _sha(pr["base"]["sha"]),
            "trigger": "push",
        },
    }


def build_check_run_input(payload, delivery):
    """The execution input for a click on our check run.

    Draft fixes re-runs the pipeline on the same commit with remediation on;
    the re-scan is a minute and changes nothing, because review state is
    preserved. Its name is (PR, commit, "fixes"), so a second click on the
    same commit starts nothing. Re-run is a plain rescan, named by the
    delivery: each click is its own delivery, and a redelivery of one click
    is the same name again.
    """
    # A check_suite.rerequested has the same two fields where this reads
    # them, on the suite instead of the run.
    check_run = payload.get("check_run") or payload["check_suite"]
    pr = check_run["pull_requests"][0]
    repo = payload["repository"]
    pr_id = make_pr_id(repo["id"], pr["number"])
    fixes = payload["action"] == "requested_action"
    trigger = "fixes" if fixes else "rerun-" + re.sub(r"[^A-Za-z0-9]", "", delivery)[:8]
    return {
        "pr_id": pr_id,
        "s3_prefix": f"scans/{pr_id}/",
        "remediate": fixes,
        "github": {
            "installation_id": int(payload["installation"]["id"]),
            "repository_id": int(repo["id"]),
            "repository": repo["full_name"],
            "pr_number": int(pr["number"]),
            # The check run's commit, not the PR's current head: the button
            # is on a result for this commit, and that is what it asks about.
            "head_sha": _sha(check_run["head_sha"]),
            "base_sha": _sha(pr["base"]["sha"]),
            "trigger": trigger,
        },
    }


def make_pr_id(repository_id, pr_number):
    """`gh-<repository id>-<PR number>`.

    The numeric id, not owner/repo: both names may contain hyphens, so
    "a-b/c" and "a/b-c" would join to the same string, and a rename would
    orphan the PR's review history. The id is unique and never changes. The
    readable name travels in the execution input instead.
    """
    return f"gh-{int(repository_id)}-{int(pr_number)}"


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _sha(value):
    if not isinstance(value, str) or not _SHA_RE.match(value):
        raise ValueError(f"not a commit sha: {value!r}")
    return value


def execution_name(pr_id, head_sha, trigger):
    """A name that is the same for the same (PR, commit, trigger), and only then.

    Step Functions refuses a second execution under a name used in the last
    90 days, which turns a redelivered webhook into a no-op without this
    function keeping any state of its own. Same alphabet and 80-character
    limit as scripts/scan.py's execution_name, whose names carry a timestamp
    and so can never collide with these.
    """
    raw = f"{pr_id}-{head_sha[:12]}-{trigger}"
    return re.sub(r"[^A-Za-z0-9_-]", "-", raw)[:80]


def _response(status, message=None):
    response = {"statusCode": status}
    if message is not None:
        response["headers"] = {"content-type": "application/json"}
        response["body"] = json.dumps({"message": message})
    return response
