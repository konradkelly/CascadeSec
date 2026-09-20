"""mapping-agent Lambda (spec §4.1, §4.4 step 4).

Maps a raw finding to an OWASP/CIS control via the Anthropic API, using
corpus/rule_mappings.json (see corpus/README.md) as a deterministic first
pass: it looks up which controls are even candidates for a given
(source, rule_id), then asks Claude to pick/cite/explain only among those
candidates -- never to invent a control_id from scratch. A finding whose
rule_id has no candidate mapping is left with status "raw" (spec's
FindingRecord status enum has no "unmapped" state); grow coverage by
extending corpus/rule_mappings.json, not by relaxing this Lambda.

Event shape:
{ "pr_id": "manual-test-1" }
-- or, continuing a pass that yielded (see `remaining` below) --
{ "pr_id": "manual-test-1", "mapped_count": 38, "files": ["ec2.tf"] }

Returns {pr_id, mapped_count, skipped_count, error_count, files, remaining}.
skipped is a decision -- no candidate, or an answer refused by the checks
below; error is a fault in one finding's mapping, which is logged and does
not stop the others. Both leave the finding "raw". "files" is the sorted
set of files a finding was mapped on: the pipeline
(terraform/step_functions.tf) fans remediation out one file per invocation,
and this is its item list. A file is the unit, not a finding, because
remediation-agent chains the fixes within a file -- see its module docstring.

One model call per finding, in sequence, and a PR can carry more of them
than the function's timeout holds (a 73-finding scan of terragoat's ec2.tf
and neighbours had 47 with candidates, ~3s each, against 120s -- the
invocation was killed mid-loop and the pipeline failed with it,
2026-09-18). So the loop yields before the clock runs out: it returns
`remaining` > 0 and the state machine invokes again. No resume token is
needed, because each mapping is written as it is made and only "raw"
findings are queried, so the table is the cursor. `mapped_count` and
`files` are carried in on the event and accumulate across passes; skipped
and error counts are the last pass's own, since everything it counts is
still raw and was looked at again.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import anthropic
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET")
ANTHROPIC_SECRET_ARN = os.environ.get("ANTHROPIC_SECRET_ARN")
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")
AGENT_NAME = "mapping-agent"
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
METRIC_NAMESPACE = "IaCPosture"

# Time a finding must have left before it starts, so the model call in
# flight is never the one the timeout lands on. One call at max_tokens=1024
# is ~3s in practice; the reserve is sized for a slow one, not a typical
# one. Default for a direct invoke; Terraform sets it.
FINDING_TIME_RESERVE_MS = int(os.environ.get("FINDING_TIME_RESERVE_SECONDS", "30")) * 1000

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
secretsmanager = boto3.client("secretsmanager")

# Cold-start caches -- corpus content and the API key don't change within a
# warm execution environment, so fetch each at most once per container.
_anthropic_client = None
_rule_mappings = None
_framework_cache = {}

_FRAMEWORK_FILES = {
    "CIS-AWS-1.4": "cis-aws-1.4.json",
    "OWASP-CloudNative": "owasp-cloud-native.json",
    "OWASP-CICD-Top10": "owasp-cicd-top10.json",
    "CIS-Kubernetes-2.0": "cis-kubernetes-2.0.json",
}

MAPPING_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "control_id": {"type": "string"},
        "framework": {"type": "string"},
        "citation": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["finding_id", "control_id", "framework", "citation", "rationale"],
    "additionalProperties": False,
}


def handler(event, context):
    pr_id = event["pr_id"]

    raw_findings = _query_raw_findings(pr_id)
    rule_mappings = _load_rule_mappings()

    # Carried over from the pass that yielded, if this is a continuation.
    mapped_count = event.get("mapped_count", 0)
    files = set(event.get("files", []))
    mapped_before = mapped_count
    skipped_count = 0
    error_count = 0
    remaining = 0

    for index, finding in enumerate(raw_findings):
        candidate_refs = rule_mappings.get(f"{finding['source']}:{finding['rule_id']}")
        if not candidate_refs:
            skipped_count += 1
            continue

        # Yield rather than be killed: a timeout mid-call loses the call and
        # the return value, and the state machine cannot tell how far the
        # pass got. Checked only where a model call is about to start --
        # findings with no candidate cost nothing and are never the reason.
        if _time_left_ms(context) < FINDING_TIME_RESERVE_MS:
            remaining = len(raw_findings) - index
            logger.info("yielding with %d raw finding(s) unexamined", remaining)
            break

        try:
            candidates = [_load_control(c["framework"], c["control_id"]) for c in candidate_refs]
            mapping = _call_mapping_agent(finding, candidates)
            if mapping is None:
                skipped_count += 1
                continue
            _write_mapping(finding, mapping)
        except Exception:
            # One finding's failure shouldn't abandon the rest of the PR. The
            # finding stays "raw", so a re-run retries it; skipped is for a
            # decision (no candidate, answer refused), this is for a fault --
            # a corpus reference that doesn't resolve, the API, DynamoDB.
            logger.exception("mapping failed for finding %s", finding.get("finding_id"))
            error_count += 1
            continue

        mapped_count += 1
        files.add(finding["file"])

    if remaining and mapped_count == mapped_before:
        # A whole time budget spent without one mapping landing is a fault
        # (the API down, every call timing out), not a workload. Asking for
        # another pass would repeat it indefinitely: the failed findings are
        # still raw and still first in the query. Stop, and say so; the
        # findings stay raw for a re-run once whatever it was is fixed.
        logger.error(
            "no finding mapped in this pass; not yielding with %d unexamined", remaining
        )
        remaining = 0

    return {
        "pr_id": pr_id,
        "mapped_count": mapped_count,
        "skipped_count": skipped_count,
        "error_count": error_count,
        "files": sorted(files),
        "remaining": remaining,
    }


def _log_usage(response, **context):
    """One Embedded Metric Format line per model call, so a run's token
    spend is a CloudWatch sum rather than an estimate. Same mechanism as
    iac-scanner's metrics (observability.tf): print(), not logger, because
    EMF needs the whole log event to be the JSON object. Priced at the
    model's rates these four numbers are the bill; cache_* are zero until
    prompt caching is turned on and then say whether it is working. The
    tests' stub responses carry no usage, hence the getattr.
    """
    usage = getattr(response, "usage", None)
    if usage is None:
        return
    metrics = {
        "InputTokens": getattr(usage, "input_tokens", 0) or 0,
        "OutputTokens": getattr(usage, "output_tokens", 0) or 0,
        "CacheReadInputTokens": getattr(usage, "cache_read_input_tokens", 0) or 0,
        "CacheCreationInputTokens": getattr(usage, "cache_creation_input_tokens", 0) or 0,
    }
    dimensions = {"Environment": ENVIRONMENT, "Agent": AGENT_NAME}
    print(json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [sorted(dimensions)],
                "Metrics": [{"Name": name, "Unit": "Count"} for name in metrics],
            }],
        },
        **dimensions, **metrics, "model": getattr(response, "model", MODEL), **context,
    }))


def _time_left_ms(context):
    """Milliseconds before Lambda kills this invocation. Unbounded outside
    Lambda (the tests pass no context), where nothing is going to kill it."""
    if context is None:
        return float("inf")
    return context.get_remaining_time_in_millis()


def _query_all(table, **kwargs):
    """Query to exhaustion. A Query caps at 1MB of read items and applies
    FilterExpression only afterwards, so one page can return few (or zero)
    matches while more wait behind a continuation token."""
    items = []
    while True:
        response = table.query(**kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return items
        kwargs["ExclusiveStartKey"] = last_key


def _query_raw_findings(pr_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    return _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        FilterExpression="#status = :status",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":pk": f"PR#{pr_id}",
            ":sk_prefix": "FINDING#",
            ":status": "raw",
        },
    )


def _load_rule_mappings():
    global _rule_mappings
    if _rule_mappings is None:
        obj = s3.get_object(Bucket=ARTIFACTS_BUCKET, Key="corpus/rule_mappings.json")
        _rule_mappings = json.loads(obj["Body"].read())["mappings"]
    return _rule_mappings


def _load_control(framework, control_id):
    key = f"corpus/frameworks/{_FRAMEWORK_FILES[framework]}"
    if key not in _framework_cache:
        obj = s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=key)
        _framework_cache[key] = json.loads(obj["Body"].read())
    control = next(c for c in _framework_cache[key]["controls"] if c["control_id"] == control_id)
    return {
        "framework": framework,
        "control_id": control_id,
        "title": control["title"],
        "text": control["text"],
        "s3_key": key,
    }


def _get_anthropic_client():
    global _anthropic_client
    if _anthropic_client is None:
        secret = secretsmanager.get_secret_value(SecretId=ANTHROPIC_SECRET_ARN)
        _anthropic_client = anthropic.Anthropic(api_key=secret["SecretString"])
    return _anthropic_client


def _call_mapping_agent(finding, candidates):
    candidates_text = "\n\n".join(
        f"- framework: {c['framework']}, control_id: {c['control_id']}\n"
        f"  title: {c['title']}\n"
        f"  text: {c['text']}"
        for c in candidates
    )

    prompt = (
        "Scanner finding:\n"
        f"  source: {finding['source']}\n"
        f"  rule_id: {finding['rule_id']}\n"
        f"  severity: {finding['severity']}\n"
        f"  file: {finding['file']}\n\n"
        "Candidate controls (pick exactly one -- the single best match):\n"
        f"{candidates_text}\n\n"
        f"Return finding_id={finding['finding_id']!r} unchanged, the framework "
        "and control_id of your chosen candidate exactly as given above, a "
        "citation that is a verbatim excerpt of under 15 words taken from "
        "that candidate's text, and a 1-2 sentence rationale that references "
        "the finding's rule_id."
    )

    response = _get_anthropic_client().messages.create(
        model=MODEL,
        max_tokens=1024,
        output_config={
            "effort": "low",
            "format": {"type": "json_schema", "schema": MAPPING_OUTPUT_SCHEMA},
        },
        messages=[{"role": "user", "content": prompt}],
    )
    _log_usage(response, finding_id=finding["finding_id"])

    text = next((b.text for b in response.content if b.type == "text"), None)
    if text is None:
        logger.error("mapping-agent got no text block for finding %s", finding["finding_id"])
        return None

    mapping = json.loads(text)

    if mapping["finding_id"] != finding["finding_id"]:
        logger.error(
            "mapping-agent finding_id mismatch for %s: got %s",
            finding["finding_id"], mapping["finding_id"],
        )
        return None

    valid = {(c["framework"], c["control_id"]) for c in candidates}
    if (mapping["framework"], mapping["control_id"]) not in valid:
        logger.error(
            "mapping-agent picked a control outside the candidate set for %s: %s/%s",
            finding["finding_id"], mapping["framework"], mapping["control_id"],
        )
        return None

    chosen = next(
        c for c in candidates
        if c["framework"] == mapping["framework"] and c["control_id"] == mapping["control_id"]
    )
    mapping["control_text_ref"] = chosen["s3_key"]
    return mapping


def _write_mapping(finding, mapping):
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"pk": finding["pk"], "sk": finding["sk"]},
        UpdateExpression="SET control_mappings = :cm, #status = :status, updated_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":cm": [{
                "framework": mapping["framework"],
                "control_id": mapping["control_id"],
                "control_text_ref": mapping["control_text_ref"],
                "citation_span": mapping["citation"],
                # Not in spec §5's abbreviated FindingRecord shorthand, but kept
                # since §1's human-review design intent needs the "why", not
                # just the citation, and the agent already produces it for free.
                "rationale": mapping["rationale"],
            }],
            ":status": "mapped",
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )
