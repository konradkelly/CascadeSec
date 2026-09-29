"""review-api Lambda (spec §4.1, §4.4 step 6).

CRUD behind API Gateway for the review dashboard: list a PR's findings, fetch
one finding with its proposed diff, record a human's approve/edit/reject
decision, and read a finding's audit trail.

This is the "human approves" half of the project's core principle -- the agent
proposes, a person disposes. Every decision writes an immutable ReviewEvent
(spec §5) alongside the status change, so nothing is silently decided.

Wired to an API Gateway HTTP API (payload format 2.0), one Lambda handling
every route via `routeKey` dispatch. Every route sits behind a Cognito JWT
authorizer, so by the time this code runs the caller has a verified identity --
which is where a review's `actor` comes from. See _actor_from_claims.
"""

import decimal
import difflib
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
METRIC_NAMESPACE = "IaCPosture"

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")

# Reviewer actions, per spec §5's ReviewEvent.action enum. "approved"/"edited"
# mean the human accepted a fix, so the finding becomes "resolved". "rejected"
# refuses the proposed fix -- the underlying finding is still real, so it
# goes to "needs-human-only" rather than staying wherever it was. It used to
# leave status untouched, which meant a finding approved and later rejected
# still read "resolved"; every consumer that needed the truth then had to
# read the event log instead. See docs/reviewer-edit-spec.md §2.4.
RESOLVING_ACTIONS = {"approved", "edited"}
VALID_ACTIONS = RESOLVING_ACTIONS | {"rejected"}


class _DecimalEncoder(json.JSONEncoder):
    """DynamoDB returns every number as Decimal, which json can't serialize."""

    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return int(o) if o % 1 == 0 else float(o)
        return super().default(o)


def handler(event, context):
    route_key = event.get("routeKey")
    params = event.get("pathParameters") or {}

    try:
        if route_key == "GET /prs/{pr_id}/findings":
            return _ok(_list_findings(params["pr_id"]))

        if route_key == "GET /prs/{pr_id}/findings/{finding_id}":
            finding = _get_finding(params["pr_id"], params["finding_id"])
            if finding is None:
                return _error(404, "finding not found")
            return _ok(finding)

        if route_key == "GET /prs/{pr_id}/findings/{finding_id}/events":
            return _ok(_list_events(params["pr_id"], params["finding_id"]))

        if route_key == "GET /prs/{pr_id}/findings/{finding_id}/content":
            return _get_content(params["pr_id"], params["finding_id"])

        if route_key == "POST /prs/{pr_id}/findings/{finding_id}/review":
            return _post_review(
                params["pr_id"], params["finding_id"], event.get("body"), event
            )

        return _error(404, f"unknown route {route_key!r}")
    except Exception:
        # Never leak internals to an HTTP client; CloudWatch has the detail.
        logger.exception("review-api failed handling %s", route_key)
        return _error(500, "internal error")


def _actor_from_claims(event):
    """The caller's identity, taken from the JWT the authorizer verified.

    API Gateway will not invoke this function unless the token's signature,
    issuer, audience and expiry all check out, so these claims are trustworthy
    in a way a request body never is. Preferring email over sub keeps the audit
    trail readable; sub is the fallback because email is only guaranteed when
    the pool is configured to require it.

    Returns None if the claims are missing entirely, which should mean the
    authorizer was removed from the route -- treated as an auth failure rather
    than quietly attributing the decision to nobody.
    """
    claims = (
        (event.get("requestContext") or {}).get("authorizer") or {}
    ).get("jwt", {}).get("claims") or {}

    actor = claims.get("email") or claims.get("cognito:username") or claims.get("sub")
    return actor or None


# ---------- routes ----------

def _list_findings(pr_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    items = _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        ExpressionAttributeValues={":pk": f"PR#{pr_id}", ":sk_prefix": "FINDING#"},
    )
    return {"pr_id": pr_id, "count": len(items), "findings": items}


def _get_finding(pr_id, finding_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    response = table.get_item(Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{finding_id}"})
    return response.get("Item")


def _event_pk(pr_id, finding_id):
    """Partition key for one finding's audit trail.

    Includes pr_id, which spec §5's `FINDING#<finding_id>` shorthand omits.
    finding_id is a content hash of the finding, so the identical rule on the
    identical file produces the identical id in every PR that scans it -- ids
    are unique within a PR, not across them. Keyed on finding_id alone, a
    decision recorded against one PR surfaces in the audit trail of every
    other PR that happens to contain the same finding, attributing decisions
    nobody made on that PR. For an audit log whose purpose is that nothing is
    silently decided, that's the one failure it cannot have.
    """
    return f"PR#{pr_id}#FINDING#{finding_id}"


def _list_events(pr_id, finding_id):
    """Audit trail for one finding, scoped to the PR it was decided on."""
    table = dynamodb.Table(DYNAMODB_TABLE)
    items = _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        ExpressionAttributeValues={":pk": _event_pk(pr_id, finding_id), ":sk_prefix": "EVENT#"},
    )
    return {"finding_id": finding_id, "count": len(items), "events": items}


def _post_review(pr_id, finding_id, raw_body, event):
    # Identity first: nothing about this request is worth parsing if we can't
    # say who made it.
    actor = _actor_from_claims(event)
    if actor is None:
        logger.error("review POST reached the handler with no verified JWT claims")
        return _error(401, "unauthenticated")

    try:
        body = json.loads(raw_body or "{}")
    except json.JSONDecodeError:
        return _error(400, "body must be valid JSON")

    action = body.get("action")
    if action not in VALID_ACTIONS:
        return _error(400, f"action must be one of {sorted(VALID_ACTIONS)}")

    # An "actor" in the body is ignored rather than honoured: it used to be the
    # source of truth, and silently preferring it again would let a caller sign
    # someone else's name to a decision.

    # A reviewer edits the corrected *file*, not the diff, and this side
    # computes the diff -- the same rule the spec applies to the LLM, for the
    # same reason: a hand-authored diff may not apply to anything, a computed
    # one always does. edited_diff is refused outright rather than accepted as
    # a fallback, because a fallback is a path, and this one produced
    # unvalidated input. See docs/reviewer-edit-spec.md §2.1.
    if "edited_diff" in body:
        return _error(400, "edited_diff is no longer accepted; send edited_content, the full corrected file")
    edited_content = body.get("edited_content")
    if action == "edited" and not edited_content:
        return _error(400, "edited_content is required when action is 'edited'")
    if action != "edited" and edited_content is not None:
        return _error(400, "edited_content is only valid when action is 'edited'")

    finding = _get_finding(pr_id, finding_id)
    if finding is None:
        return _error(404, "finding not found")

    proposed_fix = finding.get("proposed_fix")
    if action in RESOLVING_ACTIONS and proposed_fix is None:
        return _error(409, "finding has no proposed fix to act on")

    edited_diff = None
    if action == "edited":
        base = _read_base_content(pr_id, finding)
        edited_diff = _unified_diff(base, edited_content, finding["file"])
        if not edited_diff:
            return _error(400, "edited_content is identical to the fix's base; nothing to record")

    # Checked before the ReviewEvent is written: a blocked decision is not an
    # attempted decision, and should leave no trace in the audit trail.
    # Rejection is never blocked -- it is always safe, and it is the reviewer's
    # only escape hatch from a chain gone bad.
    if action in RESOLVING_ACTIONS:
        unmet = _unmet_prerequisites(pr_id, proposed_fix)
        if unmet:
            logger.info(
                "%s of finding %s blocked on prerequisites: %s", action, finding_id, unmet,
            )
            return _response(409, {
                "error": "fix depends on prerequisites that are not satisfied",
                "unmet": unmet,
            })

    now = datetime.now(timezone.utc).isoformat()
    table = dynamodb.Table(DYNAMODB_TABLE)

    # Event written before the finding is mutated: a failure partway through
    # then leaves a recoverable trace (an attempted decision with no state
    # change) rather than the reverse -- a state change nobody logged, which
    # is the failure mode spec §1 forbids.
    table.put_item(Item={
        "pk": _event_pk(pr_id, finding_id),
        "sk": f"EVENT#{now}",
        "finding_id": finding_id,
        "pr_id": pr_id,
        "actor": actor,
        "action": action,
        "notes": body.get("notes", ""),
        "edited_diff": edited_diff,
        "created_at": now,
    })

    if action == "edited":
        # Written before the record: from here on this content *is* the fix,
        # and anything rooted on the fix -- a later chain, a re-self-check --
        # reads it from here. A record that says "edited" with the agent's
        # content still in S3 would be the worse failure.
        s3.put_object(
            Bucket=ARTIFACTS_BUCKET,
            Key=_content_key(pr_id, finding_id, finding["file"]),
            Body=edited_content.encode("utf-8"),
        )

    status = "resolved" if action in RESOLVING_ACTIONS else None
    if action == "rejected" and proposed_fix is not None:
        # There was a fix and the human refused it. The finding is not
        # resolved, and it is not "fix-proposed" either -- that fix is off the
        # table. A rejection of a finding with nothing proposed (rare, but the
        # route allows it) records the event and moves nothing.
        status = "needs-human-only"

    if status is not None:
        update_expression = "SET #status = :status, updated_at = :now"
        values = {":status": status, ":now": now}

        if action == "edited":
            update_expression += ", proposed_fix = :pf"
            values[":pf"] = {
                **proposed_fix,
                "diff": edited_diff,
                # Preserved on the first edit only, never overwritten again --
                # it's the only record of what the agent actually proposed,
                # which the fix-acceptance metric (spec §7) is computed
                # against.
                "agent_diff": proposed_fix.get("agent_diff") or proposed_fix.get("diff"),
                # self_check_passed is never asserted by a human, for the same
                # reason spec §6 forbids it being asserted by the LLM: an
                # edited diff has not been through the scanner, so it cannot
                # inherit a passing check. cleared is reset alongside it --
                # neither half of the self-check is known until a scan
                # actually runs against this diff. Any self_check_passed the
                # client sent is ignored; this is computed, not accepted.
                "self_check_passed": False,
                "self_check_new_findings": [],
                "cleared": False,
                # Reset for the same reason, and load-bearing in the other
                # direction: a reviewer's most likely response to "the fix did
                # not parse" is to hand-correct the syntax, and carrying the
                # agent's parse failure onto their edit would keep reporting a
                # file that no longer exists as broken.
                "scan_errors": [],
            }

        table.update_item(
            Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{finding_id}"},
            UpdateExpression=update_expression,
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues=values,
        )

    # An edit replaces this fix's diff, so every fix drafted on top of it is
    # now rooted on content that no longer exists; a rejection means that
    # content is never landing at all. _unmet_prerequisites catches both when
    # the dependent is reviewed; it does nothing for a dependent already
    # approved, because that decision has already happened and nothing
    # re-examines it. Approve f1, approve f2, then edit or reject f1 is a
    # supported sequence -- "resolved" is not terminal and repeat decisions are
    # deliberate -- so without this the dependent sits there marked resolved
    # and unassemblable. See docs/fix-chain-review-spec.md §4.
    #
    # Two kinds of dependent. A fix drafted on top of this one (applies_after)
    # goes back to needs-human-only to be redrafted. A finding this fix
    # superseded (superseded_by) goes back to mapped: it never had a fix of its
    # own, because this one cleared its rule, and that may no longer be true.
    #
    # Not on "approved": approving leaves the diff untouched and landing, and
    # it is the diff these dependents were drafted against.
    reopened = []
    if action in ("edited", "rejected"):
        reopened = _reopen_dependents(pr_id, finding_id, action, actor, now)

    # Spec §7.3's fix-acceptance rate, as its raw counts. One metric with the
    # action as a dimension, so approved / edited / rejected are three series
    # in one namespace and the rate is a metric-math expression over them
    # rather than a fourth thing to keep consistent. Emitted after every write
    # has succeeded, so a decision that failed to record is not counted.
    _emit_metrics(
        {"ReviewDecisions": 1},
        {"Environment": ENVIRONMENT, "Action": action},
        pr_id=pr_id, finding_id=finding_id, event="review_decision",
    )

    return _ok({
        "finding_id": finding_id,
        "action": action,
        "status": status,
        "recorded_at": now,
        # Named in the response so the reviewer who caused the cascade learns
        # about it immediately, rather than finding it later in someone else's
        # queue.
        "reopened_dependents": reopened,
    })


# ---------- helpers ----------


def _emit_metrics(metrics, dimensions, **context):
    """Publish CloudWatch metrics by printing one Embedded Metric Format line.

    print(), not logger: Lambda prefixes logger output with level, timestamp
    and request id, and EMF needs the whole log event to be the JSON object.
    CloudWatch extracts the metrics from the log stream, so this costs no IAM,
    no SDK call, and no extra latency -- and the line doubles as a structured
    record of the run. Namespace and dimension names are the contract with
    terraform/observability.tf; metric names are the contract with anyone
    graphing them.
    """
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

def _content_key(pr_id, finding_id, file_path):
    """Where a fix's corrected file lives. Must match remediation-agent's
    _self_check_prefix: the agent writes its draft here for the self-check,
    and a reviewer's edit overwrites it, so one key is the fix's content
    whoever last wrote it. Under fixes/, not scans/, because scans/ expires
    and this does not get to."""
    return f"fixes/{pr_id}/{finding_id}/{file_path}"


def _read_s3(key):
    obj = s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=key)
    return obj["Body"].read().decode("utf-8")


def _read_base_content(pr_id, finding):
    """The file this fix was drafted against: the pristine snapshot for the
    first fix in a file, otherwise the output of the last fix in its chain.
    applies_after is cumulative, so the last entry's content already has every
    earlier fix applied."""
    chain = (finding.get("proposed_fix") or {}).get("applies_after") or []
    if not chain:
        return _read_s3(f"scans/{pr_id}/{finding['file']}")
    last = chain[-1]
    last_id = last.get("finding_id") if isinstance(last, dict) else last
    return _read_s3(_content_key(pr_id, last_id, finding["file"]))


def _unified_diff(base, corrected, file_path):
    """Same call remediation-agent makes, so an agent diff and a reviewer diff
    are the same kind of artifact."""
    return "".join(difflib.unified_diff(
        base.splitlines(keepends=True),
        corrected.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    ))


def _get_content(pr_id, finding_id):
    """The fix's current corrected file, for the dashboard to prefill an edit.

    Read from S3 on each request rather than stored on the record: DynamoDB's
    400KB item ceiling is not hypothetical for a module's main.tf."""
    finding = _get_finding(pr_id, finding_id)
    if finding is None:
        return _error(404, "finding not found")
    if not finding.get("proposed_fix"):
        return _error(404, "finding has no proposed fix, so no corrected content")
    try:
        content = _read_s3(_content_key(pr_id, finding_id, finding["file"]))
    except s3.exceptions.NoSuchKey:
        return _error(404, "no corrected content stored for this fix")
    return _ok({"finding_id": finding_id, "file": finding["file"], "content": content})


def _reopen_dependents(pr_id, changed_finding_id, action, actor, now):
    """Reopen everything whose state rested on this fix, after it was edited or
    rejected.

    Reads the whole PR partition, which _list_findings already does for the
    dashboard, and filters for findings that name this one. There is no
    reverse index and no need for one: chains are per-file and the partition
    is a single PR's findings.

    Two relationships qualify, and they reopen differently:

    - A fix drafted on top of this one (this id in its applies_after) goes to
      mapped with stale_reason set, so the dashboard can say *why* a fix it
      previously showed as resolved is open again. Its self-check ran against
      a base that has since changed or will never land, so it no longer
      evidences anything, whatever it concluded at the time. mapped rather
      than needs-human-only because there is nothing for a human to do with
      it: approve and edit are blocked on it (§3), and only a redraft against
      the accepted base can fix that. mapped is what remediation-agent picks
      up, and _chain_root now starts that redraft from the last accepted fix.
    - A finding this fix superseded (superseded_by == this id) goes to mapped
      and loses superseded_by. It never had a fix of its own -- this fix
      cleared its rule as a side effect, and after an edit that may no longer
      be so; after a rejection it certainly is not. The next run drafts it a
      fix for the first time. No stale_reason: there is no proposed_fix to
      put it on.

    Every reopen writes a ReviewEvent with actor "system". That event is the
    point. A machine is reopening a decision a human recorded, and an audit
    log whose purpose is that nothing is silently decided cannot let that
    happen off the books.
    """
    table = dynamodb.Table(DYNAMODB_TABLE)
    reopened = []

    if action == "edited":
        because = (
            f"Prerequisite {changed_finding_id} was edited by {actor} at {now}, "
            "so this fix is drafted against content that no longer exists. "
            "It needs redrafting against the edited base before it can be applied."
        )
        superseded_because = (
            f"The fix that had cleared this finding, {changed_finding_id}, was edited by "
            f"{actor} at {now}, so it may no longer clear it. Returned to mapped for a "
            "fix of its own."
        )
    else:
        because = (
            f"Prerequisite {changed_finding_id} was rejected by {actor} at {now}, "
            "so the base this fix is drafted against is never landing. "
            "It needs redrafting against the chain without that fix."
        )
        superseded_because = (
            f"The fix that had cleared this finding, {changed_finding_id}, was rejected by "
            f"{actor} at {now}, so nothing clears it now. Returned to mapped for a fix of "
            "its own."
        )

    candidates = _list_findings(pr_id)["findings"]
    # A chain dependent about to be redrafted may itself have superseded
    # findings -- its old draft cleared their rules as a side effect. The
    # redraft is a new draft and the claim has to be re-earned, so those are
    # reopened too. One extra hop is enough: supersede is not transitive
    # (a superseded finding has no fix to supersede anything with), and
    # applies_after is cumulative, so every chain dependent names the changed
    # fix directly. Observed live before this existed: f2 was reopened and
    # redrafted while a finding superseded by f2's *old* draft stayed
    # superseded, pointing at a diff that no longer existed.
    chain_dependent_ids = {
        c.get("finding_id") for c in candidates
        if c.get("finding_id") != changed_finding_id and any(
            (e.get("finding_id") if isinstance(e, dict) else e) == changed_finding_id
            for e in ((c.get("proposed_fix") or {}).get("applies_after") or [])
        )
    }
    supersede_roots = {changed_finding_id} | chain_dependent_ids

    for candidate in candidates:
        candidate_id = candidate.get("finding_id")
        if candidate_id == changed_finding_id:
            continue

        superseder = candidate.get("superseded_by")
        if superseder in supersede_roots:
            table.update_item(
                Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{candidate_id}"},
                UpdateExpression="SET #status = :status, updated_at = :now REMOVE superseded_by",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":status": "mapped", ":now": now},
            )
            if superseder == changed_finding_id:
                note = superseded_because
            else:
                note = (
                    f"The fix that had cleared this finding, {superseder}, is being redrafted "
                    f"because its own prerequisite {changed_finding_id} was {action} by {actor} "
                    f"at {now}. Whether the redraft still clears it is not yet known. "
                    "Returned to mapped for a fix of its own."
                )
            _write_system_event(table, pr_id, candidate_id, now, note)
            reopened.append(candidate_id)
            continue

        proposed_fix = candidate.get("proposed_fix") or {}
        chain = proposed_fix.get("applies_after") or []
        depends = any(
            (entry.get("finding_id") if isinstance(entry, dict) else entry) == changed_finding_id
            for entry in chain
        )
        if not depends:
            continue

        table.update_item(
            Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{candidate_id}"},
            UpdateExpression=(
                "SET #status = :status, proposed_fix.stale_reason = :reason, updated_at = :now"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status": "mapped",
                ":reason": because,
                ":now": now,
            },
        )
        _write_system_event(table, pr_id, candidate_id, now, because)
        reopened.append(candidate_id)

    if reopened:
        logger.info(
            "%s of %s reopened dependent findings %s", action, changed_finding_id, reopened,
        )
    return reopened


def _write_system_event(table, pr_id, finding_id, now, notes):
    table.put_item(Item={
        "pk": _event_pk(pr_id, finding_id),
        # Suffixed so a cascade cannot collide with the decision that caused
        # it, which carries the same timestamp.
        "sk": f"EVENT#{now}#system",
        "finding_id": finding_id,
        "pr_id": pr_id,
        "actor": "system",
        "action": "reopened",
        "notes": notes,
        "edited_diff": None,
        "created_at": now,
    })


def _unmet_prerequisites(pr_id, proposed_fix):
    """Prerequisites of this fix that can't currently be satisfied.

    A prerequisite is an earlier finding on the same file whose fix this one
    was drafted on top of, so this diff's context lines describe the file
    *with that fix applied*. Approving a dependent whose base never lands
    yields an approved set nobody can assemble, and until now nothing said so.

    Returns a list of {finding_id, reason}, naming every blocker at once so a
    reviewer sees the whole blocking set rather than discovering it one 409 at
    a time. Empty means every prerequisite is satisfied and unchanged.
    """
    unmet = []
    for entry in proposed_fix.get("applies_after") or []:
        # Entries were bare id strings before the chain carried hashes, and
        # findings written by that build are still readable. They can't be
        # verified, so they fail closed rather than being waved through.
        if not isinstance(entry, dict):
            unmet.append({"finding_id": str(entry), "reason": "unverifiable"})
            continue

        prerequisite_id = entry.get("finding_id")
        prerequisite = _get_finding(pr_id, prerequisite_id)
        if prerequisite is None:
            unmet.append({"finding_id": prerequisite_id, "reason": "missing"})
            continue

        # Satisfaction is the *latest* ReviewEvent, not status. status is a
        # lossy cache of the last resolving action and is never retracted: a
        # rejection deliberately leaves it alone, so approving a finding and
        # then rejecting it leaves status "resolved" while the standing
        # decision on it is a rejection. A status check reads that as
        # satisfied. The event log is the only place the truth survives.
        events = _list_events(pr_id, prerequisite_id)["events"]
        if not events:
            unmet.append({"finding_id": prerequisite_id, "reason": "undecided"})
            continue
        latest = max(events, key=lambda e: e["sk"])["action"]
        if latest not in RESOLVING_ACTIONS:
            # "reopened" is the system's doing, not a reviewer's, and the
            # remedy differs: a rejected prerequisite is dropped from the
            # chain, a reopened one is waiting to be redrafted and re-reviewed.
            reason = "reopened" if latest == "reopened" else "rejected"
            unmet.append({"finding_id": prerequisite_id, "reason": reason})
            continue

        # Absent is not the same as fresh.
        recorded_hash = entry.get("diff_sha256")
        if not recorded_hash:
            unmet.append({"finding_id": prerequisite_id, "reason": "unverifiable"})
            continue

        # Distinct from "rejected", and the distinction is actionable: a stale
        # dependent is redrafted against the new base, a rejected one against
        # the chain minus that link. A rejected prerequisite's content is
        # unchanged, so its hash still matches -- the two checks catch
        # genuinely different failures.
        prerequisite_fix = prerequisite.get("proposed_fix") or {}
        current_diff = prerequisite_fix.get("diff")
        if current_diff is None or _diff_sha256(current_diff) != recorded_hash:
            unmet.append({"finding_id": prerequisite_id, "reason": "stale"})

    return unmet


def _diff_sha256(diff_text):
    """Must stay identical to remediation-agent's helper of the same name."""
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


# ---------- the commit plan (write-back-spec §5) ----------
#
# A copy of github-committer's plan_commit and what it calls, for the
# dashboard's preview; keep the copies identical -- corpus/test_corpus.py
# asserts it. The preview reads the head from the S3 snapshot, and the
# committer re-checks every file against GitHub before it writes.

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

    Returns [{file, outcome, reason, tip, chain, left_out, content, diff}]
    sorted by file. outcome is "commit", "already" or "held"; reason says
    why a file is held. chain lists the tip's links with whether each was
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
                "left_out": [], "content": None, "diff": None}
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
        plan.update(outcome="commit", content=content, diff=_commit_diff(head, content, path))
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


def _content_sha256(content):
    """Must stay identical to remediation-agent's helper of the same name,
    which records the hash of the file a chain was drafted on."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _query_all(table, **kwargs):
    """Query to exhaustion -- a single Query caps at 1MB of items."""
    items = []
    while True:
        response = table.query(**kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return items
        kwargs["ExclusiveStartKey"] = last_key


def _ok(body):
    return _response(200, body)


def _error(status_code, message):
    return _response(status_code, {"error": message})


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body, cls=_DecimalEncoder),
    }
