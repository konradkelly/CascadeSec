"""remediation-agent Lambda (spec §4.1, §4.4 step 5; docs/remediation-agent-spec.md).

For each finding with status "mapped" under a PR, drafts a corrected version
of the offending file via the Anthropic API, computes a unified diff against
the original in code, then proves the fix works by re-invoking
iac-scanner (persist=false) against the patched content and comparing
(source, rule_id) pairs before/after. self_check_passed is always computed
here, never asserted by the LLM -- that's the project's core integrity
guarantee.

Computing it from the rescan is only sound while the rescan actually happened.
A scanner that crashed, and a file the scanner could not parse, both report
zero findings, which the comparison would read as the finding having been
cleared. So a failed invocation is raised (the finding stays "mapped" for a
retry) and a reported parse error short-circuits to needs-human-only before
any verdict is computed.

A draft may ask questions instead of guessing. The model returns
`questions` -- facts about the rest of the repository it would otherwise
have had to declare as assumptions -- and context-agent answers them from the
snapshot with citations (docs/context-agent-spec.md). The fix is then
redrafted knowing the answers. A draft with no questions costs exactly what
it did before: one call. Whatever the repository could not settle comes back
as `unknown` and holds the fix for review just as an assumption does, so the
human-review gate is unchanged -- but from the questions record, where it
reads as what it is, not copied into assumptions as a question-shaped fact.

Findings are remediated one file at a time, in a stable order, each fix
drafted against the file as the previous accepted fix left it. Every file in
the live table carries between 3 and 22 findings, so drafting each fix from
the pristine snapshot produced N competing whole-file rewrites of the same
few lines -- two of which, on demo-1, created the same resource address with
different arguments. proposed_fix.applies_after records the chain a fix was
built on.

Event shape:
{
  "pr_id": "manual-test-1",
  "file": "main.tf",              # optional: only this file's findings (the
                                  # unit the pipeline's Map state fans out on)
  "resume_from": "<finding_id>"   # optional: root the chain at this fix
                                  # rather than at the last accepted one
}

The pipeline (terraform/step_functions.tf) invokes this once per file, and a
file can hold more findings than fit in one invocation: every finding is a
model call plus a self-check scan, so 900s is roughly four to seven of them.
Rather than be killed mid-write, the handler stops when the time left would
not safely cover another finding and returns `remaining` > 0 with
`resume_from` set to the last scanner-verified fix. The state machine feeds
that output straight back in as the next input -- a continuation token -- and
the chain carries on from where it stopped instead of restarting from the
snapshot. The counts are cumulative across continuations for the same reason.
"""

import collections
import difflib
import hashlib
import json
import logging
import os
import re
import time
import typing
from datetime import datetime, timezone

import anthropic
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET")
ANTHROPIC_SECRET_ARN = os.environ.get("ANTHROPIC_SECRET_ARN")
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")
AGENT_NAME = "remediation-agent"
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
METRIC_NAMESPACE = "IaCPosture"
IAC_SCANNER_FUNCTION_NAME = os.environ.get("IAC_SCANNER_FUNCTION_NAME")
# Unset means questions are not asked: the model is told not to raise any,
# and a draft that does anyway is used as-is, its questions recorded as
# asked-and-unanswered (which holds the fix). Lets the two components deploy
# independently.
CONTEXT_AGENT_FUNCTION_NAME = os.environ.get("CONTEXT_AGENT_FUNCTION_NAME")

# Time to leave on the clock before starting another finding: the
# self-check scan's timeout, context-agent's timeout, and two model calls
# (draft and redraft) at a worst case of ~2 minutes each. A finding that
# starts with this much left cannot be cut off by the Lambda timeout.
# Terraform sets it from the other functions' timeouts so the numbers cannot
# drift apart; the default here is only for a direct invoke without it.
FINDING_TIME_RESERVE_MS = int(os.environ.get("FINDING_TIME_RESERVE_SECONDS", "690")) * 1000

# How many fixes one run may draft for one file. Superseded findings are
# free and do not count; only a model call does. Past the budget a finding
# is written as not-drafted, with the reason, and picked up again by the
# next run -- where, once the drafted fixes are accepted, most of them are
# superseded at baseline 0 without a call, and the rest get a fresh budget.
#
# Sized from measurement, not guessed (multi-iac-spec §5, 2026-09-19): a
# PugetScope Deployment carries 22 mapped findings that need 5 distinct
# edits, one of which clears 16 of the 22. The budget is the backstop for
# the case where the model drafts them one field at a time instead -- ~16
# calls for the securityContext family alone -- not the expected path. It is
# per file because files are remediated in parallel (Map, concurrency 4) and
# this invocation cannot see the others.
MAX_DRAFTS_PER_FILE = int(os.environ.get("MAX_DRAFTS_PER_FILE", "8"))

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
secretsmanager = boto3.client("secretsmanager")
lambda_client = boto3.client("lambda")

# Cold-start cache -- the API key doesn't change within a warm execution
# environment, so fetch it at most once per container (same pattern as
# mapping-agent).
_anthropic_client = None

class _Outcome(typing.NamedTuple):
    """What one finding's remediation produced.

    final_passed is the verdict written to the record; scanner_verified is
    the narrower question of whether the rescan proved this fix cleared its
    finding without introducing new ones. They differ whenever a
    human-review gate (a deleted resource, a declared assumption) overrides
    a clean rescan, and only the second one decides whether this fix becomes
    the base for the next finding in the file -- see handler().
    """
    final_passed: bool
    scanner_verified: bool
    content: str | None
    rescan_counts: "collections.Counter | None"
    # (source, rule_id, resource) for every rescan finding that names its
    # resource -- see _present_triples. The counts say how many times a rule
    # fires; this says on what.
    rescan_triples: "set | None"
    # This fix's diff, kept so the next fix in the file can record a hash of
    # it in its own applies_after. Only set when scanner_verified, for the
    # same reason content is: an unverified fix never becomes a base.
    diff: str | None


REMEDIATION_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "corrected_file_content": {"type": "string"},
        "rationale": {"type": "string"},
        # Facts the fix depends on that couldn't be checked against the one
        # file the agent was given, AND whose falsity would break something.
        # Schema-required so the model has to answer rather than quietly fold
        # a guess into fluent prose. A non-empty list forces human review --
        # see _remediate_finding.
        #
        # The breakage test is doing real work in the prompt. Asking merely
        # for "unverifiable facts" made every fix declare four of them,
        # including provider-version notes and "SSE-S3 is transparent to
        # clients", so nothing ever passed and the list became boilerplate to
        # skim past -- which is how the one that matters gets missed.
        "assumptions": {"type": "array", "items": {"type": "string"}},
        # Assumptions the repository itself could settle. Each is answered by
        # context-agent with a citation and the fix is redrafted; the ones
        # the repository cannot settle come back as unknown and hold the fix
        # from the questions record. See _remediate_finding.
        "questions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["corrected_file_content", "rationale", "assumptions", "questions"],
    "additionalProperties": False,
}

# `resource "<type>" "<name>" {` -- enough for counting blocks; this is a
# guard, not an HCL parser.
RESOURCE_BLOCK_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)

# The Kubernetes equivalents, and the same deal: a guard, not a YAML parser.
# There is no PyYAML in the runtime or the layer, and a parser would be the
# wrong tool anyway -- a Helm template is not valid YAML until rendered, and
# the guard has to hold on the file the agent actually edited. What it
# needs is a document's `kind` and `metadata.name`, and both are structural
# enough to read off the lines: a manifest's own `kind:` sits at column 0,
# where a RoleBinding's `subjects[].kind` or a `roleRef.kind` is indented;
# its own `metadata:` sits at column 0, where a pod template's is indented.
# Documents are split on `---`. The \r? is for manifests committed from
# Windows: the snapshot is the file as the repository holds it.
K8S_DOC_SEPARATOR_RE = re.compile(r"^---[ \t]*\r?$", re.MULTILINE)
K8S_KIND_RE = re.compile(r"^kind:[ \t]*(\S+)", re.MULTILINE)
K8S_METADATA_RE = re.compile(r"^metadata:[ \t]*\r?$", re.MULTILINE)

# Bicep. A guard, not a parser, for the same reason the Kubernetes one is:
# pycep-parser lives in the scanner image next to checkov, not in this
# function's runtime or layer.
#
# `resource <symbolicName> '<type>@<apiVersion>' = {`, with `= if (...)` and
# `= [for x in y: {` variants after the closing quote and an `existing`
# keyword before it -- none of which the match has to reach, so it stops at
# the quote and all three forms are covered without enumerating them.
# `^[ \t]*` rather than `^` so a nested child resource counts: deleting one
# is the same class of edit as deleting a top-level one. `[ \t]` rather than
# `\s` so a `\r` can never be eaten as the next line's indent.
BICEP_RESOURCE_RE = re.compile(
    r"^[ \t]*resource[ \t]+([A-Za-z_]\w*)[ \t]+'([^'@]+)@[^']*'", re.MULTILINE)
# A module deploys a whole sub-template, so deleting one is more of this
# gate's business than deleting a single resource, not less.
BICEP_MODULE_RE = re.compile(
    r"^[ \t]*module[ \t]+([A-Za-z_]\w*)[ \t]+'([^']+)'", re.MULTILINE)


def handler(event, context):
    pr_id = event["pr_id"]
    only_file = event.get("file")
    resume_from = event.get("resume_from")
    if resume_from and not only_file:
        # A fix belongs to one file, so a chain can only be resumed per file.
        raise ValueError("resume_from requires file")

    mapped_findings = _query_mapped_findings(pr_id, only_file)

    # Counters start from the previous continuation's, so the number the
    # state machine reports for a file is the file's total, not the last
    # invocation's share of it. A first invocation carries none of these.
    fix_proposed_count = event.get("fix_proposed_count", 0)
    needs_human_count = event.get("needs_human_only_count", 0)
    superseded_count = event.get("superseded_count", 0)
    not_drafted_count = event.get("not_drafted_count", 0)
    error_count = event.get("error_count", 0)
    # How many of this invocation's findings were left untouched, and the fix
    # the next invocation should root at. Both stay at their defaults unless
    # the time budget stops the loop.
    remaining = 0
    resume_at = None

    for file_path, findings in _group_by_file(mapped_findings):
        if remaining:
            # Out of time on an earlier file (whole-PR mode only; per-file
            # mode has one file). Counted so the caller knows work is left.
            remaining += len(findings)
            continue
        try:
            base_content, baseline_counts, baseline_triples, applies_after = _chain_root(
                pr_id, file_path, resume_from,
            )
            # The scanner's line numbers refer to this, not to the chain's
            # content -- see _flagged_lines.
            original_content = _fetch_original_content(pr_id, file_path)
        except Exception:
            # Nothing in this file can be remediated without its base, and the
            # failure is the file's, not any one finding's.
            logger.exception("could not establish the chain root for %s", file_path)
            error_count += len(findings)
            continue
        # (source, rule_id) -> the fix that took it to zero in this run. Rules
        # overlap between and within the two scanners, so one fix routinely
        # clears more than its own finding: on demo-1, CKV_AWS_145 wants KMS
        # and aws-s3-enable-bucket-encryption wants any encryption, so a KMS
        # fix satisfies both.
        cleared_by = {}
        # (source, rule_id, resource) -> the fix that stopped the rule firing
        # on that resource. The per-resource form of cleared_by, for files
        # where one rule fires on several resources and a fix settles one of
        # them at a time -- see _present_triples.
        resolved_by = {}
        # Drafts this run has already spent on this file. In per-file mode the
        # counters carried in from a continuation are this file's, so the
        # budget spans continuations; in whole-PR mode they are the PR's, and
        # the budget is per invocation.
        drafted = (fix_proposed_count + needs_human_count) if only_file else 0

        for index, finding in enumerate(findings):
            # Yield rather than be killed. A timeout mid-finding would lose
            # the model call in flight and, worse, leave no return value, so
            # the state machine could not tell where the chain got to. The
            # check is before the finding starts because that is the only
            # point where stopping costs nothing.
            if _time_left_ms(context) < FINDING_TIME_RESERVE_MS:
                remaining = len(findings) - index
                resume_at = applies_after[-1]["finding_id"] if applies_after else None
                logger.info(
                    "yielding on %s with %d finding(s) left; chain resumes at %s",
                    file_path, remaining, resume_at,
                )
                break

            # An earlier fix in this file already removed this rule, so there
            # is nothing left to fix. Remediating anyway is not just wasted:
            # the model is handed a file where the issue is already gone,
            # returns it unchanged, and _evaluate_self_check compares a rescan
            # count of 0 against a baseline of 0 -- `0 < 0` is False, so a
            # finding that is genuinely resolved would be written up as a fix
            # that failed to clear it.
            target = (finding.get("source"), finding.get("rule_id"))
            # cleared_by only knows about fixes drafted in this run. A rule the
            # accepted chain already took to zero -- which is what a baseline
            # of 0 means when there is a root -- was cleared by that chain, and
            # the root is the fix whose content was just rescanned to prove it.
            # Observed live before this existed: two findings an approved fix
            # had cleared were drafted anyway, the model returned the file
            # unchanged saying the rule was already satisfied, and the empty
            # diff was scored `cleared=False`.
            if target not in cleared_by and applies_after and baseline_counts[target] == 0:
                cleared_by[target] = applies_after[-1]["finding_id"]
            superseded_by = cleared_by.get(target)
            # The same question per resource, for the rule that is still
            # firing elsewhere in the file. Only asked when the baseline
            # names resources at all: a rescan from a scanner without the
            # field would leave the set empty, and "not in an empty set"
            # would supersede everything behind the first fix.
            triple = target + (finding.get("resource"),)
            if superseded_by is None and finding.get("resource") and baseline_triples:
                if triple not in resolved_by and applies_after and triple not in baseline_triples:
                    resolved_by[triple] = applies_after[-1]["finding_id"]
                superseded_by = resolved_by.get(triple)
            if superseded_by is not None:
                logger.info(
                    "finding %s superseded by %s", finding["finding_id"], superseded_by,
                )
                _write_superseded(finding, superseded_by)
                superseded_count += 1
                continue

            # Checked after the supersede, not before: a superseded finding
            # costs nothing, and telling it "over budget" would hide that an
            # earlier fix already resolved it.
            if drafted >= MAX_DRAFTS_PER_FILE:
                logger.info(
                    "finding %s not drafted: %d of %d drafts spent on %s",
                    finding["finding_id"], drafted, MAX_DRAFTS_PER_FILE, file_path,
                )
                _write_not_drafted(finding, drafted)
                not_drafted_count += 1
                continue

            try:
                outcome = _remediate_finding(
                    pr_id, finding, base_content, baseline_counts, list(applies_after),
                    _flagged_lines(original_content, finding),
                )
            except Exception:
                # One finding's failure shouldn't abandon the rest of the file.
                # Status stays "mapped", so a re-run retries this finding. The
                # chain is not advanced, so the next finding is drafted against
                # the same base as this one was.
                logger.exception("remediation failed for finding %s", finding.get("finding_id"))
                error_count += 1
                continue

            drafted += 1
            if outcome.final_passed:
                fix_proposed_count += 1
            else:
                needs_human_count += 1

            # scanner_verified, not final_passed: a fix held for human review
            # because it deletes a resource or rests on an assumption is still
            # a coherent edit that cleared its finding, and the next fix should
            # build on it. A fix the scanner rejected -- suppression, unparseable,
            # didn't clear, introduced new findings -- is not, and would poison
            # every fix after it in this file.
            if outcome.scanner_verified:
                # Record what this fix took to zero before the baseline moves,
                # so a later finding on one of those rules can be told which
                # fix resolved it rather than just that it is gone.
                for pair, previous in baseline_counts.items():
                    if previous > 0 and outcome.rescan_counts[pair] == 0:
                        cleared_by[pair] = finding["finding_id"]
                for triple in baseline_triples - outcome.rescan_triples:
                    resolved_by[triple] = finding["finding_id"]

                base_content = outcome.content
                baseline_counts = outcome.rescan_counts
                baseline_triples = outcome.rescan_triples
                # The hash is what makes staleness detectable at review time:
                # review-api compares it against the prerequisite's *current*
                # diff, so a reviewer editing an earlier fix invalidates every
                # fix drafted on top of it without either side reconstructing
                # file content. See docs/fix-chain-review-spec.md §2.
                applies_after.append({
                    "finding_id": finding["finding_id"],
                    "diff_sha256": _diff_sha256(outcome.diff),
                })

    result = {
        "pr_id": pr_id,
        "fix_proposed_count": fix_proposed_count,
        "needs_human_only_count": needs_human_count,
        "superseded_count": superseded_count,
        "not_drafted_count": not_drafted_count,
        "error_count": error_count,
        # Non-zero means "invoke me again with this output as the input".
        "remaining": remaining,
    }
    if only_file:
        result["file"] = only_file
        # Only meaningful per file: a whole-PR invocation that ran out of time
        # reports how much is left, and a re-invoke roots where it always did.
        if remaining and resume_at:
            result["resume_from"] = resume_at
    return result


def _time_left_ms(context):
    """Milliseconds before Lambda kills this invocation. Unbounded outside
    Lambda (the tests pass no context), where nothing is going to kill it."""
    if context is None:
        return float("inf")
    return context.get_remaining_time_in_millis()


def _group_by_file(findings):
    """Findings grouped by file, each group in a stable remediation order.

    The order decides which fix every later fix is drafted against, so it has
    to be deterministic: a re-run that shuffled it would produce a different
    chain, and different diffs, from identical inputs. Sorted by position in
    the file, then by identity to break ties between two rules on one line.
    """
    groups = collections.defaultdict(list)
    for finding in findings:
        groups[finding["file"]].append(finding)
    for file_path in sorted(groups):
        yield file_path, sorted(groups[file_path], key=_remediation_order)


def _remediation_order(finding):
    line_range = finding.get("line_range") or []
    start = line_range[0] if line_range else None
    # Both halves of line_range can be null (a rule that names a file rather
    # than a line), and DynamoDB hands the numbers back as Decimal.
    return (
        int(start) if start is not None else 0,
        finding.get("source", ""),
        finding.get("rule_id", ""),
        finding["finding_id"],
    )


def _remediate_finding(pr_id, finding, base_content, baseline_counts, applies_after, flagged=""):
    finding_id = finding["finding_id"]
    file_path = finding["file"]

    # base_content is the file as the previous accepted fix in this file left
    # it, not the pristine snapshot, so the model is shown what it is actually
    # editing and the diff is minimal against that.
    remediation = _call_remediation_agent(finding, base_content, flagged=flagged)
    questions = remediation.get("questions") or []
    answers = []
    if questions and CONTEXT_AGENT_FUNCTION_NAME:
        # The draft above was made without knowing these. Ask, then draft
        # again with the answers in front of the model.
        answers = _ask_context_agent(pr_id, questions)
        remediation = _call_remediation_agent(finding, base_content, answers, flagged=flagged)
        # A redraft may not ask again: there is no second lookup, so whatever
        # it still wants to know is recorded as asked and unanswered.
        answers += [_not_looked_up(q, "Asked after the lookup; there is no second one.")
                    for q in remediation.get("questions") or []]
    elif questions:
        answers = [_not_looked_up(q, "No context-agent is deployed to answer it.") for q in questions]
    corrected_content = remediation["corrected_file_content"]
    rationale = remediation["rationale"]
    # The model's own claims, and nothing else. A question the repository
    # could not settle is not folded in here as a question-shaped "fact":
    # it stays in the questions record as unknown, and holds the fix from
    # there (below). One list, one meaning -- and no duplicate when the model
    # has already restated the unanswered question as the claim it relies on.
    assumptions = list(remediation.get("assumptions") or [])
    unanswered = [a["question"] for a in answers if a["answer"] == "unknown"]

    diff_text = _compute_diff(base_content, corrected_content, file_path)

    # Gate before the self-check, not after: a suppression would *pass* the
    # self-check by construction, so there is no point scanning it.
    suppressions = _find_added_suppressions(diff_text)
    if suppressions:
        logger.warning(
            "remediation for finding %s tried to suppress the scanner rather than fix it: %s",
            finding_id, suppressions,
        )
        _write_result(
            finding, diff_text, rationale,
            self_check_passed=False, self_check_new_findings=[], cleared=False,
            suppression_attempt=suppressions, applies_after=applies_after,
            questions=answers,
        )
        return _Outcome(False, False, None, None, None, None)

    _upload_scratch_file(pr_id, finding_id, file_path, corrected_content)
    rescan_findings, scan_errors = _invoke_self_check(pr_id, finding_id)

    # The scanner could not parse what the agent wrote. An unparseable file
    # yields no findings, and _evaluate_self_check reads no findings as "the
    # rule stopped firing" -- so a fix that breaks the syntax outright would
    # otherwise come back self_check_passed=True, exactly the false pass the
    # suppression gate above exists to prevent. Nothing was proven here, so
    # there is no verdict to compute: return before evaluating.
    if scan_errors:
        logger.warning(
            "remediation for finding %s did not parse: %s", finding_id, scan_errors,
        )
        _write_result(
            finding, diff_text, rationale,
            self_check_passed=False, self_check_new_findings=[], cleared=False,
            assumptions=assumptions, scan_errors=scan_errors,
            applies_after=applies_after, questions=answers,
        )
        return _Outcome(False, False, None, None, None, None)

    self_check_passed, self_check_new_findings, cleared = _evaluate_self_check(
        finding, rescan_findings, baseline_counts
    )
    # Kept so an accepted fix can hand its own finding set to the next fix in
    # this file as that fix's baseline.
    rescan_counts = _count_pairs(rescan_findings)
    scanner_verified = self_check_passed

    # A clean rescan proves the finding is gone. It says nothing about whether
    # the infrastructure still works, and these two cases are exactly where
    # that gap bites: a deleted resource always scans clean, and a fix resting
    # on an unverifiable claim scans clean whether or not the claim is true.
    # Both stay proposals a human has to weigh, so the verdict is overridden
    # even when the scanner is satisfied. Scanned first regardless -- the
    # rescan result is still worth showing the reviewer.
    # A record from before the target_type split has none, and was Terraform
    # by construction: nothing else was admitted to the scanner then.
    dropped_resources = _find_dropped_resources(
        base_content, corrected_content, finding.get("target_type", "terraform")
    )
    # An unanswered question is the third gate: "we looked and the
    # repository does not say" is still something the fix may rest on, and
    # the model is not trusted to decide that it does not.
    if dropped_resources or assumptions or unanswered:
        logger.info(
            "finding %s held for human review (dropped=%s, assumptions=%s, unanswered=%s)",
            finding_id, dropped_resources, assumptions, unanswered,
        )
        self_check_passed = False

    _write_result(
        finding, diff_text, rationale, self_check_passed, self_check_new_findings, cleared,
        dropped_resources=dropped_resources, assumptions=assumptions,
        applies_after=applies_after, questions=answers,
    )
    return _Outcome(
        self_check_passed,
        scanner_verified,
        corrected_content if scanner_verified else None,
        rescan_counts if scanner_verified else None,
        _present_triples(rescan_findings) if scanner_verified else None,
        diff_text if scanner_verified else None,
    )


def _query_all(table, **kwargs):
    """Query to exhaustion. A Query caps at 1MB of read items and applies
    FilterExpression only afterwards, so one page can return few (or zero)
    matches while more wait behind a continuation token. Under-reading the
    baseline below would weaken the "no new findings" half of the self-check."""
    items = []
    while True:
        response = table.query(**kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return items
        kwargs["ExclusiveStartKey"] = last_key


def _chain_root(pr_id, file_path, resume_from=None):
    """Where this file's chain starts: (content, finding counts, finding
    triples, applies_after).

    The pristine snapshot, unless a fix on this file has already been accepted
    -- then the chain starts from the *last* accepted fix's corrected file, so
    everything drafted now is drafted on top of what a reviewer has already
    said yes to. That is what makes a reopened dependent recoverable: after a
    reviewer edits f1, f2 goes back to mapped and is redrafted here against
    the edited f1, not against a snapshot that never had f1 in it.
    docs/reviewer-edit-spec.md §2.3.

    Accepted means status "resolved", which is trustworthy now that a
    rejection retracts it (review-api). Among several resolved fixes on one
    file the last is the one with the longest chain: applies_after is
    cumulative, so the longest one has every other applied already.

    resume_from overrides that: it names the fix a previous invocation of
    this same run stopped after (see handler), and the chain roots there
    regardless of its status. A fix drafted ten minutes ago and not yet
    reviewed is exactly as good a base as it was when the previous invocation
    built on it -- rooting at the accepted fix instead would redraft the rest
    of the file as competing rewrites of the same lines, which is the problem
    the chain exists to prevent.

    The counts for the root are the finding set of its content. For the
    snapshot that is the original scan, already in the table. For a fix it is
    a rescan: the fix's own self-check counts are stale if a reviewer edited
    it, and the difference is exactly the case this exists for, so it is not
    worth the two code paths to skip the invoke when it would be safe.
    """
    on_file = _query_findings_on_file(pr_id, file_path)
    if resume_from:
        root = next((f for f in on_file if f["finding_id"] == resume_from), None)
        if root is None or not (root.get("proposed_fix") or {}).get("diff"):
            raise RuntimeError(f"resume_from {resume_from} is not a drafted fix on {file_path}")
    else:
        accepted = [
            f for f in on_file
            if f.get("status") == "resolved" and (f.get("proposed_fix") or {}).get("diff")
        ]
        if not accepted:
            # The original scan's counts, across every status. Counts rather
            # than a set: one file often carries several instances of the same
            # rule (three open-ingress rules in one security group, say), and
            # the self-check has to distinguish "one of them was fixed" from
            # "none".
            counts = _count_pairs(on_file)
            return _fetch_original_content(pr_id, file_path), counts, _present_triples(on_file), []
        root = max(accepted, key=lambda f: len(f["proposed_fix"].get("applies_after") or []))

    root_id = root["finding_id"]
    logger.info(
        "chain for %s roots at %s fix %s",
        file_path, "resumed" if resume_from else "accepted", root_id,
    )

    key = f"{_self_check_prefix(pr_id, root_id)}{file_path}"
    content = s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=key)["Body"].read().decode("utf-8")

    rescan_findings, scan_errors = _invoke_self_check(pr_id, root_id)
    if scan_errors:
        # The accepted content does not parse. Most likely a reviewer's edit
        # broke it. Nothing can be drafted on a base the scanner cannot read.
        raise RuntimeError(f"root fix {root_id} does not parse: {scan_errors}")
    counts = _count_pairs(rescan_findings)

    chain = list(root["proposed_fix"].get("applies_after") or [])
    chain.append({"finding_id": root_id, "diff_sha256": _diff_sha256(root["proposed_fix"]["diff"])})
    return content, counts, _present_triples(rescan_findings), chain


def _query_findings_on_file(pr_id, file_path):
    table = dynamodb.Table(DYNAMODB_TABLE)
    return _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        FilterExpression="#file = :file",
        ExpressionAttributeNames={"#file": "file"},
        ExpressionAttributeValues={
            ":pk": f"PR#{pr_id}",
            ":sk_prefix": "FINDING#",
            ":file": file_path,
        },
    )


def _query_mapped_findings(pr_id, only_file=None):
    """Findings with a control and no fix yet: mapped, and not-drafted from a
    run whose budget for the file ran out. Both are the same thing to this
    loop -- something to draft, or to supersede if a fix already cleared it."""
    table = dynamodb.Table(DYNAMODB_TABLE)
    names = {"#status": "status"}
    values = {":pk": f"PR#{pr_id}", ":sk_prefix": "FINDING#",
              ":status": "mapped", ":not_drafted": "not-drafted"}
    filter_expression = "#status IN (:status, :not_drafted)"
    if only_file:
        names["#file"] = "file"
        values[":file"] = only_file
        filter_expression += " AND #file = :file"
    return _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        FilterExpression=filter_expression,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def _flagged_lines(original_content, finding, context=2):
    """The finding's lines as they were in the file the scanner read, numbered.

    A finding's line_range is relative to the pristine snapshot, but every
    fix after the first in a file is drafted against the chain's content,
    and a fix that inserts lines above the finding moves everything below it.
    Observed on pugetscope-ctx-2: the first fix added a locals block near the
    top, and the port-80 finding's "line 48" then pointed into the 6443
    rule, which is what got fixed. The model is given the original text and
    told to find it by content, not by number.

    Empty when the finding has no line (some rules name a file) or the range
    is off the end of the file, which is a different problem from drift and
    is left to the model to notice.
    """
    line_range = finding.get("line_range") or []
    start = line_range[0] if line_range else None
    if start is None:
        return ""
    lines = original_content.splitlines()
    start = int(start)
    end = int(line_range[1]) if len(line_range) > 1 and line_range[1] is not None else start
    if start < 1 or start > len(lines):
        return ""
    lo = max(start - context, 1)
    hi = min(end + context, len(lines))
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(lo, hi + 1))


def _fetch_original_content(pr_id, file_path):
    obj = s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=f"scans/{pr_id}/{file_path}")
    return obj["Body"].read().decode("utf-8")


def _get_anthropic_client():
    global _anthropic_client
    if _anthropic_client is None:
        secret = secretsmanager.get_secret_value(SecretId=ANTHROPIC_SECRET_ARN)
        _anthropic_client = anthropic.Anthropic(api_key=secret["SecretString"])
    return _anthropic_client


def _ask_context_agent(pr_id, questions):
    """context-agent's answers, in question order. A failed invocation is
    raised: the finding stays "mapped" for a retry, which beats drafting on
    an answer that was never given."""
    payload = {"pr_id": pr_id, "s3_prefix": f"scans/{pr_id}/", "questions": questions}
    response = lambda_client.invoke(
        FunctionName=CONTEXT_AGENT_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    result = json.loads(response["Payload"].read())
    if "FunctionError" in response:
        raise RuntimeError(f"context-agent invocation failed: {result}")
    return result["answers"]


def _not_looked_up(question, why):
    """A question that was asked but never put to the repository, in the
    shape of an answer, so the questions record is the one place every
    question the draft raised can be found."""
    return {"question": question, "answer": "unknown", "explanation": why, "citations": []}


def _format_answers(answers):
    lines = []
    for a in answers:
        lines.append(f"Q: {a['question']}")
        lines.append(f"A: {a['answer']} -- {a['explanation']}")
        for c in a.get("citations") or []:
            start, end = c["line_range"]
            lines.append(f"   [{c['file']}:{start}-{end}] {c['excerpt']}")
    return "\n".join(lines)


def _describe_rule(finding):
    """The lines that say what the rule means, for the prompt.

    The id alone is not enough. Trivy's are numbers, and on terragoat's
    s3.tf (2026-09-21) the model, given `rule_id: AWS-0091` and nothing
    else, added versioning -- AWS-0091 is "ignore public ACLs" -- and for
    AWS-0093 (restrict public buckets) added encryption. Seven of the file's
    fixes were for a rule other than the one flagged, and the self-check
    held every one of them. The ec2 and eks rules it had guessed right; the
    S3 family it had not. So the scanner's own title and description travel
    with the finding (iac-scanner _build_finding), and the control the
    finding was mapped to says what the fix has to satisfy in the
    framework's words. A record from before those fields existed still
    works: it gets the id and whatever mapping it has.
    """
    lines = []
    if finding.get("title"):
        lines.append(f"  title: {finding['title']}")
    if finding.get("description"):
        lines.append(f"  description: {finding['description']}")
    if finding.get("resource"):
        lines.append(f"  resource: {finding['resource']}")
    for m in finding.get("control_mappings") or []:
        if m.get("framework") and m.get("control_id"):
            span = f" -- {m['citation_span']}" if m.get("citation_span") else ""
            lines.append(f"  mapped control: {m['framework']} {m['control_id']}{span}")
    return "".join(line + "\n" for line in lines)


def _call_remediation_agent(finding, original_content, answers=None, flagged=""):
    prompt = (
        "Scanner finding to fix:\n"
        f"  source: {finding['source']}\n"
        f"  rule_id: {finding['rule_id']}\n"
        f"{_describe_rule(finding)}"
        f"  severity: {finding['severity']}\n"
        f"  file: {finding['file']}\n"
        f"  line_range: {finding['line_range']}\n\n"
    )
    if flagged:
        prompt += (
            "The line numbers above are from the file as the scanner read it. "
            "The file below may differ: earlier fixes in this file have been "
            "applied to it, and lines may have moved. The flagged lines, as "
            "they were when scanned, with their original numbers:\n"
            f"{flagged}\n\n"
            "Locate that configuration in the file below by its content, not by "
            "line number, and fix that -- not whatever now sits at those "
            "numbers.\n\n"
        )
    prompt += (
        f"Current file contents:\n{original_content}\n\n"
        "Return the complete corrected file content with a minimal fix for "
        "this specific finding only -- do not restructure unrelated code or "
        "address other findings in the file. Return the full file, not a "
        "diff or a snippet. Also return a short rationale for the fix.\n\n"
        # Observed on demo-1: fixing aws-s3-block-public-acls added an
        # aws_s3_bucket_public_access_block with only block_public_acls set,
        # and CKV_AWS_54/55/56 fired on the three attributes left out. They
        # could not fire before, because the resource did not exist. The
        # self-check correctly held the fix -- minimality itself had created
        # the findings. See spec §8.3.
        "One exception to minimality: if the fix means adding a resource or "
        "block that did not exist, configure it completely rather than "
        "setting only the one attribute this finding names. Scanners check "
        "such a resource attribute by attribute, so a half-configured one "
        "raises a finding for every attribute left out -- attributes that "
        "were not findings before, because there was no resource to check. "
        "Completing something you are already adding is not scope creep; it "
        "is the smaller change. This does not license touching resources the "
        "fix does not need to add.\n\n"
        "Fix the underlying configuration. Never silence the scanner: do not "
        "add tfsec:ignore, trivy:ignore, checkov:skip, nosec, or any other "
        "suppression comment. If you believe the flagged configuration is "
        "intentional and correct as written, say so in the rationale and "
        "return the file unchanged -- a human will decide. Suppressing a "
        "finding is not a fix and will be rejected.\n\n"
        "Prefer constraining a resource over removing it. Deleting a rule or "
        "resource always satisfies the scanner, but may remove something the "
        "running system depends on. Only delete when the resource is "
        "genuinely unnecessary, and say so explicitly in the rationale.\n\n"
        "You are shown ONE file. You cannot see the rest of the repository, "
        "the running infrastructure, or how any of this is used. Never present "
        "a guess about any of that as established fact in the rationale.\n\n"
        "In `assumptions`, list ONLY claims that meet BOTH tests:\n"
        "  (a) you could not verify it from the file above, AND\n"
        "  (b) if it turned out to be false, applying this fix would break "
        "the running system or leave the finding unfixed.\n"
        "Examples that qualify: that a port being closed won't break "
        "certificate issuance or health checks; that no other system depends "
        "on a rule you narrowed; that traffic reaches the service by some "
        "other path.\n"
        "Do NOT list: provider or module version expectations, naming and "
        "style choices, alternative approaches the reader might prefer, "
        "generic best-practice caveats, or restatements of what the fix does. "
        "Those belong in the rationale if they are worth saying at all.\n"
        "An empty list is the correct and expected answer for a "
        "self-contained fix. Every entry costs a human's attention, so a list "
        "padded with things that cannot actually break anything is worse than "
        "no list at all -- it buries the one that matters."
    )
    if answers is not None:
        # The redraft. The answers are cited facts about the repository; the
        # model is to use them, not to re-ask.
        prompt += (
            "\n\nYou asked about the rest of the repository and it was read for "
            "you. Each answer below cites the file and lines it rests on; "
            "`unknown` means the repository does not say.\n\n"
            f"{_format_answers(answers)}\n\n"
            "Draft the fix knowing this. A `yes` or `no` answer is established "
            "and must not appear in `assumptions`. A question answered "
            "`unknown` is still an assumption if the fix depends on it -- keep "
            "it there, worded as the claim you are relying on. If an answer "
            "shows the flagged configuration is required by the system as the "
            "repository describes it -- a port a certificate solver needs open, "
            "a source a caller depends on -- do not gate it off behind a new "
            "input that defaults to closed: that satisfies the scanner and "
            "breaks the deployment. Say so in the rationale and return the file "
            "unchanged; a human decides. Return an empty `questions` list: there "
            "is no second lookup."
        )
    elif CONTEXT_AGENT_FUNCTION_NAME:
        prompt += (
            "\n\nBefore settling an assumption, consider whether another file "
            "in this repository would answer it: a variables file, a .tfvars, "
            "the module that calls this one, a Kubernetes manifest, a bucket "
            "policy. If so, put it in `questions` instead of `assumptions` -- "
            "one specific question each, naming the identifier, answerable "
            "yes or no from the repository's text. They will be answered with "
            "citations and you will draft again. Questions that meet the "
            "assumptions test above are the only ones worth asking; the same "
            "rule about padding applies."
        )
    else:
        prompt += "\n\nReturn an empty `questions` list."

    response = _get_anthropic_client().messages.create(
        model=MODEL,
        # Carries a whole rewritten .tf file -- a truncated response fails
        # JSON parsing and wastes the finding's remediation attempt.
        max_tokens=16000,
        output_config={
            "effort": "medium",
            "format": {"type": "json_schema", "schema": REMEDIATION_OUTPUT_SCHEMA},
        },
        messages=[{"role": "user", "content": prompt}],
    )
    _log_usage(response, finding_id=finding["finding_id"], call="redraft" if answers else "draft")

    text = next((b.text for b in response.content if b.type == "text"), None)
    if text is None:
        raise RuntimeError(f"remediation-agent got no text block for finding {finding['finding_id']}")

    return json.loads(text)


# Directives that make a scanner stop reporting a finding without changing
# any infrastructure. tfsec and checkov are what this project runs; trivy is
# tfsec's successor and accepts the same comment under its own name.
#
# One set for every language rather than one per target_type, on purpose: a
# marker is a substring of an added line, so the union costs nothing but a
# held-for-review on the odd .tf file that gains a Kubernetes annotation,
# while a per-language set is exactly the shape that fails open when a
# language is added to the scanner and not here (multi-iac-spec §4). What
# each language needs, so the set can be audited when one is added:
#   Terraform/OpenTofu  -- HCL comments: tfsec:ignore, trivy:ignore,
#                          checkov:skip, nosec.
#   Kubernetes/Helm     -- trivy:ignore and checkov:skip work as YAML
#                          comments too, and checkov additionally reads the
#                          `checkov.io/skipN: CKV_K8S_..=reason` annotation
#                          under metadata.annotations. The annotation is the
#                          one that is not a comment, so it is the one an
#                          HCL-shaped set misses.
#   ARM                 -- strict JSON has no comment syntax at all, so every
#                          marker above is unreachable by construction.
#                          checkov reads a resource-level
#                            "metadata": {"checkov": {"skip": [
#                                {"id": "CKV_AZURE_3", "comment": "..."}]}}
#                          -- measured 2026-09-22 against the pinned checkov
#                          3.3.16: CKV_AZURE_3 moved from failed_checks to
#                          skipped_checks. Its added lines carry the quoted
#                          token "checkov" and NOT the substring
#                          checkov:skip, so `"checkov"` is the entry that an
#                          HCL- and YAML-shaped set misses. Trivy's only ARM
#                          suppression is .trivyignore, a separate file the
#                          agent cannot write: it returns one file's
#                          corrected content and nothing else.
#   ARM/Bicep (KICS)    -- KICS reads `kics-scan ignore-line`,
#                          `ignore-block` and `disable=<query-id>` comments.
#                          Measured 2026-09-23 against the pinned v2.1.20:
#                          none of them are honoured on Bicep or ARM, so the
#                          marker is decorative there today. It is in the set
#                          anyway, for the reason the set is a union at all --
#                          a marker that costs a held-for-review when it is
#                          early is the right side to be wrong on, and this
#                          one stops being decorative the moment KICS wires
#                          comment handling into its Bicep parser.
#   Bicep               -- // comments, so checkov:skip is reached as it is
#                          in HCL and no entry is needed. Measured the same
#                          day: the comment must sit INSIDE the resource
#                          body to be honoured (above the declaration it is
#                          ignored, as are `# checkov:skip` and a `//` with a
#                          space). Either way the added line contains
#                          checkov:skip, which is what this set matches on.
#                          checkov-only language -- Trivy has no Bicep
#                          scanner -- so there is no trivy:ignore to cover.
SUPPRESSION_MARKERS = ("tfsec:ignore", "trivy:ignore", "checkov:skip", "checkov.io/skip",
                       '"checkov"', "kics-scan", "nosec")


def _find_added_suppressions(diff_text):
    """Suppression directives the fix would ADD, if any.

    This is the one edit that defeats the integrity guarantee outright. The
    self-check asks "does the scanner still report this finding" -- so a diff
    that merely silences the rule clears the finding, introduces no new ones,
    and comes back self_check_passed=true. The agent would earn a
    scanner-verified badge for changing nothing.

    Observed on real code: asked to fix a CRITICAL 0.0.0.0/0 ingress rule, the
    agent left the CIDR untouched and added `#tfsec:ignore:` plus a confident
    justification. It was caught only because that file happened to hold three
    instances of the rule, so the rescan still reported it -- an accident, not
    a defence, and one that _evaluate_self_check's occurrence counting now
    (correctly) removes.

    Enforced here rather than only forbidden in the prompt: the whole premise
    of the project is that the model's output is checked by code, not trusted.

    Only added lines are examined -- a suppression already in the file is the
    author's decision and none of this function's business.
    """
    added = [
        line[1:]
        for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    return [
        line.strip()
        for line in added
        if any(marker in line.lower() for marker in SUPPRESSION_MARKERS)
    ]


def _find_dropped_resources(original_content, corrected_content, target_type):
    """Resources the fix deletes outright, rather than tightening in place.

    Deleting a resource always satisfies the self-check -- the finding is gone
    because the thing that raised it is gone -- so the scanner cannot tell
    "narrowed the CIDR" from "removed the rule". Those are different risk
    classes, and only one of them can take a service down.

    Observed on real code: asked to fix an open port 80 ingress rule, the
    agent deleted it and asserted that certificate issuance used DNS-01. The
    repo's cert-manager ClusterIssuer uses HTTP-01, which needs port 80
    reachable, so applying it would have broken TLS renewal ~60 days later.
    The self-check passed it cleanly.

    Compared per resource *type*, not per address, so renaming a resource
    (a delete plus an add, as in a legitimate
    nodeport_from_internet -> nodeport_from_admin rescope) isn't mistaken for
    a deletion. Returns the addresses that vanished ("<type>.<name>" for
    Terraform, "<Kind>/<name>" for Kubernetes, "<type>/<name>" for ARM and
    Bicep -- see TARGET_TYPE_ADDRESS_JOIN), so a reviewer sees which ones,
    but only reports when the type's count actually falls.

    Dispatches on target_type, and refuses one it has no reader for. The
    HCL regex matches nothing in YAML, so without the dispatch an agent could
    delete a whole Deployment and this would return [] -- the gate failing
    open, which multi-iac-spec §4 names as worse than not scanning the
    language at all. Raising keeps the admission list honest: a language
    reaches here only once its reader exists.
    """
    reader = STRUCTURAL_READERS.get(target_type)
    if reader is None:
        raise ValueError(
            f"no structural guard for target_type {target_type!r}; "
            "a language is not admitted to remediation until one exists"
        )
    before, after = reader(original_content), reader(corrected_content)

    before_types = collections.Counter(t for t, _ in before)
    after_types = collections.Counter(t for t, _ in after)
    if not any(after_types[t] < n for t, n in before_types.items()):
        return []

    vanished = set(before) - set(after)
    shrunk = {t for t, n in before_types.items() if after_types[t] < n}
    join = TARGET_TYPE_ADDRESS_JOIN.get(target_type, ".")
    return sorted(f"{t}{join}{n}" for t, n in vanished if t in shrunk)


def _hcl_resources(content):
    """(type, name) per `resource` block."""
    return RESOURCE_BLOCK_RE.findall(content)


def _k8s_resources(content):
    """(kind, name) per YAML document, read structurally (see K8S_KIND_RE).

    A document with no column-0 `kind:` is not a manifest (a values file, a
    comment-only trailer after the last `---`) and is skipped; one with a
    kind but no readable name still counts, under an empty name, so deleting
    it is not free. In a Helm template the name is often `{{ .Release.Name
    }}`, which is fine -- it only has to be stable between the two versions.
    """
    found = []
    for doc in K8S_DOC_SEPARATOR_RE.split(content):
        kind = K8S_KIND_RE.search(doc)
        if not kind:
            continue
        found.append((kind.group(1), _k8s_metadata_name(doc)))
    return found


def _k8s_metadata_name(doc):
    """`metadata.name` of one document: the `name:` at the first child
    indent of the column-0 `metadata:` block, stopping at the next column-0
    line. `labels: {name: ..}` sits one indent deeper and is not it."""
    meta = K8S_METADATA_RE.search(doc)
    if not meta:
        return ""
    child_indent = None
    for line in doc[meta.end():].splitlines()[1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if child_indent is None:
            child_indent = indent
        if indent == child_indent and line.lstrip().startswith("name:"):
            return line.split(":", 1)[1].strip()
    return ""


def _arm_resources(content):
    """(type, name) per ARM resource declaration, including nested children.

    A real parser rather than the line-based reader Kubernetes uses, because
    both of that reader's reasons are absent here: json is in the standard
    library where PyYAML is in neither this runtime nor its layer, and there
    is no ARM equivalent of an unrendered Helm template -- a file that is not
    valid JSON is not an ARM template at all.

    Raises rather than returning [] when it does not parse. An empty list
    here means "this fix deletes nothing", and handing that verdict to a file
    nobody could read is the gate failing open -- the thing the dispatch in
    _find_dropped_resources exists to make impossible. A raise costs the one
    finding an error_count and never a scanner-verified badge. In practice
    the self-check returns on scan_errors before reaching this, because
    iac-scanner reports an admitted .json that will not parse; this is the
    backstop for when it does not.

    `resources` is a list in every ARM schema up to languageVersion 1.0 and a
    symbolic-name object from 2.0, so both are read. Child resources nest
    under their parent's own `resources` and are reported under their own
    declared type, uncomposed, which is enough for a count. A `copy` loop is
    one declaration however many resources it deploys, which is what this
    wants -- the gate counts what the file says, not what Azure would create.
    """
    try:
        doc = json.loads(content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(
            f"ARM template did not parse, so nothing can be proven about it: {exc}"
        ) from exc
    if not isinstance(doc, dict):
        raise ValueError("ARM template is not a JSON object")
    return _arm_resource_entries(doc.get("resources"))


def _arm_resource_entries(resources):
    """The `resources` of one template or one resource, recursively.

    A name like "[parameters('storageAccountName')]" is kept verbatim, as the
    Kubernetes reader keeps `{{ include "web.fullname" . }}`: it only has to
    be stable between the two versions of the file.
    """
    found = []
    if isinstance(resources, dict):
        resources = list(resources.values())
    if not isinstance(resources, list):
        return found
    for entry in resources:
        if not isinstance(entry, dict):
            continue
        rtype = entry.get("type")
        if not isinstance(rtype, str):
            continue
        name = entry.get("name")
        found.append((rtype, name if isinstance(name, str) else ""))
        found += _arm_resource_entries(entry.get("resources"))
    return found


def _bicep_resources(content):
    """(type, symbolicName) per resource, plus ("module", name) per module.

    The symbolic name rather than the deployed `name:` property, because it
    is what the rest of the file refers to, it is on the declaration line,
    and the deployed name is usually an interpolation anyway.

    An `existing` reference counts: it is a declaration, and over-reporting
    only ever holds a fix for review where under-reporting is the failure
    this gate exists to prevent. Modules count under a synthetic "module"
    type rather than under their path -- the comparison in
    _find_dropped_resources is per type, and keying on the path would report
    a legitimate re-point at a different module as a deletion, the same false
    positive the rename case exists to avoid.
    """
    found = [(rtype, name) for name, rtype in BICEP_RESOURCE_RE.findall(content)]
    found += [("module", name) for name, _path in BICEP_MODULE_RE.findall(content)]
    return found


K8S_TARGET_TYPES = ("kubernetes", "helm")
# target_type -> reader. Adding a language to the scanner's admission list
# means adding it here, or _find_dropped_resources refuses it.
STRUCTURAL_READERS = {
    "terraform": _hcl_resources,
    "opentofu": _hcl_resources,
    **{t: _k8s_resources for t in K8S_TARGET_TYPES},
    "arm": _arm_resources,
    "bicep": _bicep_resources,
}
# How an address is written back to a reviewer, per language. Terraform's own
# form is type.name and Kubernetes' is Kind/name. ARM and Bicep both take the
# slash: an ARM type already contains dots (Microsoft.Storage/storageAccounts),
# so a dot join would read as part of the type, where a slash makes the
# address look like the resource id the reviewer already knows.
TARGET_TYPE_ADDRESS_JOIN = {
    **{t: "/" for t in K8S_TARGET_TYPES},
    "arm": "/",
    "bicep": "/",
}


def _compute_diff(original_content, corrected_content, file_path):
    diff_lines = difflib.unified_diff(
        original_content.splitlines(keepends=True),
        corrected_content.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff_lines)


def _self_check_prefix(pr_id, finding_id):
    """Where one fix's corrected file lives, and the prefix the self-check
    scans.

    Not under `scans/<pr_id>/`: the scanner lists that recursively and takes
    every .tf under it, so a copy there would be read as source by the next
    scan. Not under `scans/` at all any more: that prefix expires at 90 days,
    an S3 lifecycle rule cannot exempt a sub-prefix, and this file is no
    longer scratch -- it is the fix's content, read back as the base for every
    fix drafted on top of it and overwritten by a reviewer's edit. review-api's
    _content_key must build the identical key.
    """
    return f"fixes/{pr_id}/{finding_id}/"


def _upload_scratch_file(pr_id, finding_id, file_path, content):
    key = f"{_self_check_prefix(pr_id, finding_id)}{file_path}"
    s3.put_object(Bucket=ARTIFACTS_BUCKET, Key=key, Body=content.encode("utf-8"))
    return key


def _invoke_self_check(pr_id, finding_id):
    payload = {
        "pr_id": f"{pr_id}-self-check-{finding_id}",
        "s3_prefix": _self_check_prefix(pr_id, finding_id),
        "persist": False,
    }
    response = lambda_client.invoke(
        FunctionName=IAC_SCANNER_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    result = json.loads(response["Payload"].read())
    if "FunctionError" in response:
        # Covers iac-scanner's ScannerError -- a tool that crashed or
        # timed out rather than one that scanned clean. Raising leaves the
        # finding at status "mapped" so a re-run retries it, which is the right
        # outcome: nothing was learned about this fix either way.
        raise RuntimeError(f"iac-scanner self-check invocation failed: {result}")
    # scan_errors is absent from responses produced before the scanner reported
    # it; treated as "none known" rather than defaulting the check to failed.
    return result["findings"], result.get("scan_errors") or []


def _count_pairs(findings):
    """Occurrence counts by (source, rule_id), one per finding id.

    The scanner's raw list and the table disagree about how many findings a
    file has: _write_findings keeps one record per id, and an id hashes the
    location but not the resource, so a rule that fires several times at one
    line range -- Trivy's AWS-0038 once per missing EKS log type, five at the
    same cluster -- is five in a scan response and one in the table. A
    baseline read from the table compared against a rescan counted raw saw
    "four new findings" on every fix to terragoat's eks.tf (2026-09-18), and
    no fix to that file could pass. Counting both sides the way the table
    does is the comparison that means something; ids are the unit everywhere
    else in this project. Findings without an id (the tests' stubs) are
    counted as they come.
    """
    seen = set()
    counts = collections.Counter()
    for f in findings:
        finding_id = f.get("finding_id")
        if finding_id is not None:
            if finding_id in seen:
                continue
            seen.add(finding_id)
        counts[(f["source"], f["rule_id"])] += 1
    return counts


def _present_triples(findings):
    """(source, rule_id, resource) for every finding that names its resource.

    Counts by (source, rule_id) cannot say *which* instance of a rule a fix
    removed, only that there is one fewer. That was enough while the rule
    reaching zero was the question. It is not enough to tell that a rule is
    already settled for the resource this finding is about: terragoat's
    s3.tf (2026-09-21) holds five buckets, CKV2_AWS_6's fix for each added a
    fully configured public-access block, and that also satisfies Trivy's
    four block-public-access rules on that bucket -- but takes AWS-0086
    from 5 to 4, never to 0, so each of the thirteen findings a chained
    fix had already resolved was drafted anyway, the model returned the file
    unchanged, and `rescan < baseline` scored it as a fix that failed. The
    resource address is what tells those thirteen apart from the ones still
    firing on a bucket nothing has touched.

    A finding without a resource (a secret, or a record from before the
    scanner carried the field) is not in the set, and the count-based
    supersede in handler() still covers it.
    """
    return {
        (f["source"], f["rule_id"], f["resource"])
        for f in findings if f.get("resource")
    }


def _evaluate_self_check(finding, rescan_findings, baseline_counts):
    target_pair = (finding["source"], finding["rule_id"])
    rescan_counts = _count_pairs(rescan_findings)

    # Occurrence counts, not mere presence. A file can hold several instances
    # of one rule, and fixing the flagged instance leaves the others firing --
    # presence alone would report a real fix as uncleared. The inverse matters
    # more: a rule appearing fewer times than before means an instance
    # genuinely went away, which presence can't see at all.
    cleared = rescan_counts[target_pair] < baseline_counts[target_pair]

    # "New" covers a rule absent from the baseline *and* extra instances of one
    # already there -- a fix that doubles an existing problem isn't clean.
    new_pairs = {
        pair for pair, n in rescan_counts.items() if n > baseline_counts.get(pair, 0)
    }
    no_new_findings = not new_pairs

    self_check_passed = cleared and no_new_findings
    self_check_new_findings = sorted(f"{source}:{rule_id}" for source, rule_id in new_pairs)
    # cleared is returned separately from self_check_passed because a failed
    # self-check has two different meanings a reviewer needs told apart: the
    # fix missed the original finding entirely (cleared=False), or it cleared
    # the original but brought new findings with it (cleared=True) -- the
    # latter is often one edit away from passing, the former is not. Losing
    # this distinction and collapsing both into "self-check failed" is
    # actively misleading, not just less informative.
    return self_check_passed, self_check_new_findings, cleared


def _write_superseded(finding, superseded_by):
    """Record that another fix in this file already cleared this finding.

    No proposed_fix is written, because none was drafted -- there was nothing
    left to draft against. That also makes review-api refuse an approve or
    edit on this finding (it 409s when proposed_fix is absent), which is the
    right refusal: the decision to make is on the superseding fix, not here.

    Not "resolved": that status means a human accepted something. This is the
    scanner reporting the rule no longer fires, and it holds only for as long
    as the superseding fix does -- if that fix is rejected, this finding comes
    back. superseded_by is stored so that reversal can find it.
    """
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"pk": finding["pk"], "sk": finding["sk"]},
        UpdateExpression=(
            "SET #status = :status, superseded_by = :by, updated_at = :now"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": "superseded",
            ":by": superseded_by,
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )


def _write_not_drafted(finding, drafted):
    """Record that the file's draft budget ran out before this finding.

    Like superseded, no proposed_fix is written and review-api refuses an
    approve or edit on it. Unlike superseded, nothing has been decided about
    it -- so the status is its own, not folded into `mapped` where it would
    read as "still waiting" and never surface as the count spec §8.1 asks
    for. The next run queries it back up with the mapped ones.
    """
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"pk": finding["pk"], "sk": finding["sk"]},
        UpdateExpression=(
            "SET #status = :status, not_drafted_reason = :reason, updated_at = :now"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": "not-drafted",
            ":reason": f"file draft budget reached ({drafted} of {MAX_DRAFTS_PER_FILE})",
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )


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


def _diff_sha256(diff_text):
    """Hash of a fix's diff, recorded by every fix drafted on top of it.

    Hashing the diff rather than the resulting file content is deliberate: the
    alternative would make review-api reconstruct the base by applying the
    approved chain, i.e. implement diff application inside a Lambda. Because
    applies_after carries the cumulative chain rather than just the immediate
    predecessor, matching every recorded hash is enough to prove the composed
    base is bit-identical -- each fix's output is fixed by its own base and
    diff, and the first base is the scan snapshot, which is written once per
    run into a versioned bucket. See docs/fix-chain-review-spec.md §3.
    """
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


def _write_result(
    finding, diff_text, rationale, self_check_passed, self_check_new_findings, cleared,
    suppression_attempt=None, dropped_resources=None, assumptions=None, scan_errors=None,
    applies_after=None, questions=None,
):
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"pk": finding["pk"], "sk": finding["sk"]},
        UpdateExpression="SET proposed_fix = :pf, #status = :status, updated_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":pf": {
                "diff": diff_text,
                "rationale": rationale,
                "self_check_passed": self_check_passed,
                "self_check_new_findings": self_check_new_findings,
                "cleared": cleared,
                # Non-empty means the fix was refused before it was ever
                # scanned, because it tried to silence the rule. Surfaced so a
                # reviewer sees why rather than an unexplained failed check.
                "suppression_attempt": suppression_attempt or [],
                # Resources the fix deletes outright, and facts it depends on
                # but couldn't verify. Either one forces human review no
                # matter how clean the rescan came back.
                "dropped_resources": dropped_resources or [],
                "assumptions": assumptions or [],
                # The fixes, in order, that this one is drafted on top of --
                # empty means it applies to the pristine file. Every file in
                # this project carries several findings, so most fixes are not
                # independent: applying this diff without these first will not
                # apply cleanly, and approving it without them lands a fix
                # whose context never existed. Each entry is
                # {finding_id, diff_sha256}; the hash is what lets review-api
                # tell "prerequisite was edited" from "prerequisite is intact".
                "applies_after": applies_after or [],
                # Files the scanner couldn't parse. Non-empty means the fix was
                # never actually verified -- distinct from a fix that was
                # verified and failed, which is what a reviewer would otherwise
                # assume from self_check_passed=False.
                "scan_errors": scan_errors or [],
                # What the draft asked about the repository and what it was
                # told, citations included. Distinct from assumptions, which
                # are the model's own claims: these were put to the
                # repository. An unknown here holds the fix on its own, the
                # same way an assumption does; it is not copied into
                # assumptions as a question-shaped fact.
                "questions": questions or [],
            },
            ":status": "fix-proposed" if self_check_passed else "needs-human-only",
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )
