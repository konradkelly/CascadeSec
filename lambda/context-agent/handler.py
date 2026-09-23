"""context-agent Lambda (docs/context-agent-spec.md).

Answers bounded questions about a repository snapshot by reading it, and
cites the file and lines every answer came from. remediation-agent calls it
for the questions its model would otherwise have had to leave as
`assumptions` -- "does anything serve this bucket anonymously", "is
var.admin_cidrs populated" -- so a fix can be drafted on what the repository
says rather than on a guess.

It decides nothing. It does not originate findings (spec §8.1 is untouched),
judge fixes, or relax the self-check. It retrieves and cites. The pattern is
mapping-agent's applied to source: the model may only conclude from what it
was shown, and every "yes" or "no" carries a citation whose excerpt is
checked, in code, against the cited lines. A citation that does not verify
is dropped, and an answer left without one becomes "unknown" -- a confident
answer resting on a fabricated citation is the one failure that would make
this component worse than not having it.

Retrieval is a short tool loop over the snapshot in S3: a regex search
across the files and whole-or-partial file reads, both capped (calls, bytes,
matches), with "unknown" the required answer for anything the cap cut off.
Secret-looking values are redacted before the model sees them -- .tfvars is
in the snapshot precisely because that is where credentials live.

Event shape:
{
  "pr_id": "manual-1",
  "s3_prefix": "scans/manual-1/",
  "questions": ["Does anything in this repository ...?"]
}

Returns {"answers": [{"question", "answer", "explanation", "citations"}]}
with one entry per question, in order; citations are
{"file", "line_range": [start, end], "excerpt"}.
"""

import json
import logging
import os
import re
import shutil
import time
import uuid

import anthropic
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET")
ANTHROPIC_SECRET_ARN = os.environ.get("ANTHROPIC_SECRET_ARN")
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
METRIC_NAMESPACE = "IaCPosture"
AGENT_NAME = "context-agent"

# What the agent may read. The scanner's snapshot suffixes plus the manifests
# the motivating assumptions needed (cert-manager issuers, ingress). Anything
# else under the prefix is ignored, whatever scripts/scan.py uploaded.
CONTEXT_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json",
                    ".tofu", ".tofu.json", ".yaml", ".yml", ".bicep")

# ARM templates are .json, which says nothing on its own, so they are admitted
# by content like everywhere else: a top-level $schema naming a
# deploymentTemplate. Sniffed after the download because a listing carries no
# content, and the file is removed again if it is not a template -- a lockfile
# offered to the model as repository context is noise at best, and this agent
# quotes what it reads back as a citation. Must match iac-scanner's
# ARM_SCHEMA_RE; corpus/test_corpus.py asserts every copy agrees.
ARM_SCHEMA_RE = re.compile(r'"\$schema"\s*:\s*"[^"]*deploymentTemplate\.json')

# The caps. A question like "what depends on this" can match half a
# repository, and a truncated search that answers confidently is the
# fabrication risk wearing a different hat -- so the caps are told to the
# model, and hitting one makes "unknown" the correct answer.
MAX_TOOL_CALLS = 8
MAX_MATCHES_PER_SEARCH = 40
MAX_READ_LINES = 300
MAX_TOTAL_BYTES = 200_000
# One snapshot is small, but a runaway upload should not be downloaded whole.
MAX_SNAPSHOT_FILES = 400

# Values on lines like `password = "..."` / `token: ...` are replaced before
# the model sees them. The key names are the ones checkov's secrets scan and
# common sense agree on; a value that is a variable reference (var.x,
# data.x) is not a secret and is left alone so the agent can follow it.
SECRET_KEY_RE = re.compile(
    r'^(?P<lead>\s*"?[\w.\-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[\w.\-]*"?\s*[=:]\s*)'
    r'(?P<value>"[^"]*"|\'[^\']*\'|[^\s#]+)',
    re.IGNORECASE,
)
REDACTED = '"<redacted>"'

s3 = boto3.client("s3")
secretsmanager = boto3.client("secretsmanager")

_anthropic_client = None


ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "answers": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "question": {"type": "string"},
                    "answer": {"type": "string", "enum": ["yes", "no", "unknown"]},
                    "explanation": {"type": "string"},
                    "citations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                # [start, end]. The API's structured-output
                                # grammar rejects minItems/maxItems other
                                # than 0 or 1, so the pair is checked in
                                # _citation_verifies instead.
                                "line_range": {"type": "array", "items": {"type": "integer"}},
                                "excerpt": {"type": "string"},
                            },
                            "required": ["file", "line_range", "excerpt"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["question", "answer", "explanation", "citations"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["answers"],
    "additionalProperties": False,
}

TOOLS = [
    {
        "name": "search",
        "description": (
            "Regular-expression search across every file in the repository snapshot. "
            f"Returns up to {MAX_MATCHES_PER_SEARCH} matches as `file:line: text`, and says "
            "when there were more. Case-insensitive. Use it to find where an identifier, "
            "resource, variable or string is defined or referenced before reading a file."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}},
            "required": ["pattern"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_file",
        "description": (
            f"Read a file from the snapshot, numbered by line. At most {MAX_READ_LINES} lines "
            "per call; pass start_line to read further. Cite from what this returns -- "
            "excerpts must be verbatim text from the lines you cite."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer"},
            },
            "required": ["path", "start_line"],
            "additionalProperties": False,
        },
    },
]


def handler(event, context):
    pr_id = event["pr_id"]
    s3_prefix = event["s3_prefix"].rstrip("/") + "/"
    questions = list(event.get("questions") or [])
    if not questions:
        return {"pr_id": pr_id, "answers": []}

    work_dir = f"/tmp/context-{uuid.uuid4().hex}"
    os.makedirs(work_dir, exist_ok=True)
    try:
        files = _download_snapshot(ARTIFACTS_BUCKET, s3_prefix, work_dir)
        snapshot = Snapshot(work_dir, files)
        answers = _ask(snapshot, questions)

        result = _align(questions, answers)
        # Verified while the files are still on disk.
        verified, rejected = _verify_citations(result, snapshot)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    _emit_metrics(
        {
            "ContextQuestions": len(questions),
            "ContextAnswered": sum(1 for a in verified if a["answer"] != "unknown"),
            "ContextCitationsRejected": rejected,
        },
        {"Environment": ENVIRONMENT},
        pr_id=pr_id, event="context_complete",
    )
    return {"pr_id": pr_id, "answers": verified}


class Snapshot:
    """The downloaded files, with the two tools and the byte budget."""

    def __init__(self, root, files):
        self.root = root
        self.files = sorted(files)  # relative paths
        self.bytes_returned = 0

    def search(self, pattern):
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return f"invalid regular expression: {exc}"
        matches = []
        truncated = False
        for rel in self.files:
            for lineno, line in enumerate(self._lines(rel), 1):
                if rx.search(line):
                    if len(matches) >= MAX_MATCHES_PER_SEARCH:
                        truncated = True
                        break
                    matches.append(f"{rel}:{lineno}: {_redact(line.rstrip())}")
            if truncated:
                break
        if not matches:
            return "no matches"
        text = "\n".join(matches)
        if truncated:
            text += f"\n... more than {MAX_MATCHES_PER_SEARCH} matches; narrow the pattern"
        return self._charge(text)

    def read_file(self, path, start_line=1):
        rel = path.lstrip("/")
        if rel not in self.files:
            return f"no such file in the snapshot: {path}. Files: " + ", ".join(self.files[:50])
        lines = self._lines(rel)
        start = max(int(start_line or 1), 1)
        end = min(start + MAX_READ_LINES - 1, len(lines))
        if start > len(lines):
            return f"{rel} has {len(lines)} lines"
        body = "\n".join(f"{n}: {_redact(lines[n - 1].rstrip())}" for n in range(start, end + 1))
        if end < len(lines):
            body += f"\n... {len(lines) - end} more lines; call again with start_line={end + 1}"
        return self._charge(body)

    def lines(self, rel):
        """Raw lines of a file, for citation verification. Unredacted, since
        the model was shown the redacted text and a citation of a redacted
        line will verify against neither; that is the intended outcome."""
        return self._lines(rel) if rel in self.files else None

    def _lines(self, rel):
        with open(os.path.join(self.root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()

    def _charge(self, text):
        self.bytes_returned += len(text.encode("utf-8"))
        if self.bytes_returned > MAX_TOTAL_BYTES:
            return (
                "retrieval budget exhausted: no further content can be returned. "
                "Answer from what you have already seen, and answer `unknown` for "
                "anything not yet established."
            )
        return text


def _redact(line):
    m = SECRET_KEY_RE.match(line)
    if not m:
        return line
    value = m.group("value")
    # A reference, not a literal: var.db_password, data.aws_secretsmanager...
    if re.match(r"^(var|local|data|module|aws_)[\w.]*", value.strip("\"'")):
        return line
    return line[: m.start("value")] + REDACTED + line[m.end("value"):]


def _ask(snapshot, questions):
    """The retrieval loop: search and read until the model answers, within
    the caps. Returns the model's answers, unverified."""
    numbered = "\n".join(f"{i + 1}. {q}" for i, q in enumerate(questions))
    listing = "\n".join(snapshot.files)
    prompt = (
        "You are answering questions about an infrastructure repository by "
        "reading it. You can only conclude from text you have actually "
        "retrieved with the tools; you know nothing about this repository "
        "otherwise, and nothing about the running system.\n\n"
        f"Files in the snapshot:\n{listing}\n\n"
        f"Questions:\n{numbered}\n\n"
        f"You have at most {MAX_TOOL_CALLS} tool calls in total, and a limited "
        "byte budget. Search first, then read only what you need.\n\n"
        "Answer each question `yes`, `no`, or `unknown`.\n"
        "- `yes` and `no` REQUIRE at least one citation: the file, the line "
        "range, and an excerpt of under 20 words copied verbatim from those "
        "lines as read_file returned them. Citations are checked mechanically "
        "against the file; an excerpt that is not verbatim is discarded, and "
        "an answer with no surviving citation becomes `unknown`.\n"
        "- `unknown` is the correct answer whenever the repository does not "
        "say, whenever the answer would depend on something outside it (the "
        "running cluster, external DNS, an operator's intent), or whenever "
        "a cap cut your search short. Never infer an answer from absence "
        "unless you searched for the thing and the search was complete.\n"
        "- The explanation is one or two sentences stating what the cited "
        "lines establish. Do not recommend changes; that is not your job.\n"
        "Return the answers in the same order as the questions, quoting each "
        "question verbatim."
    )
    messages = [{"role": "user", "content": prompt}]
    client = _get_anthropic_client()
    calls = 0
    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=8000,
            tools=TOOLS,
            output_config={
                "effort": "medium",
                "format": {"type": "json_schema", "schema": ANSWER_SCHEMA},
            },
            messages=messages,
        )
        _log_usage(response, turn=calls)
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if response.stop_reason != "tool_use" or not tool_uses:
            text = next((b.text for b in response.content if b.type == "text"), None)
            if text is None:
                raise RuntimeError("context-agent got no text block in the final response")
            return json.loads(text)["answers"]

        messages.append({"role": "assistant", "content": response.content})
        results = []
        for use in tool_uses:
            calls += 1
            if calls > MAX_TOOL_CALLS:
                content = (
                    f"tool-call budget of {MAX_TOOL_CALLS} exhausted. Answer now from what "
                    "you have seen; anything not established is `unknown`."
                )
            elif use.name == "search":
                content = snapshot.search(use.input["pattern"])
            elif use.name == "read_file":
                content = snapshot.read_file(use.input["path"], use.input.get("start_line", 1))
            else:
                content = f"unknown tool {use.name}"
            results.append({"type": "tool_result", "tool_use_id": use.id, "content": content})
        messages.append({"role": "user", "content": results})


def _align(questions, answers):
    """One answer per input question, in input order, each carrying the
    question as it was asked.

    Alignment is part of the contract: remediation-agent pairs answers with
    questions by position, and stores the question text the reviewer will
    read. The model is told to quote each question verbatim, and mostly
    does; when it returned exactly one answer per question, position is
    trusted over wording, because a paraphrase is not a missing answer.
    Observed on pugetscope-ctx-2: one reworded question was recorded as
    "the agent returned no answer" under exact-text matching. With any other
    count, exact text is the only safe key and the rest are unknown.
    """
    if len(answers) == len(questions):
        return [{**a, "question": q} for q, a in zip(questions, answers)]
    by_question = {a["question"]: a for a in answers}
    return [
        by_question.get(q) or _unknown(q, "The agent returned no answer for this question.")
        for q in questions
    ]


def _verify_citations(answers, snapshot):
    """Drop any citation whose excerpt is not in the cited lines, and turn a
    yes/no left without citations into unknown. Returns (answers, rejected)."""
    rejected = 0
    out = []
    for a in answers:
        kept = []
        for c in a.get("citations") or []:
            if _citation_verifies(c, snapshot):
                kept.append({"file": c["file"].lstrip("/"), "line_range": [int(c["line_range"][0]), int(c["line_range"][1])], "excerpt": c["excerpt"]})
            else:
                rejected += 1
                logger.warning("rejected citation %s", c)
        answer = a["answer"]
        explanation = a.get("explanation", "")
        if answer in ("yes", "no") and not kept:
            answer = "unknown"
            explanation = (explanation + " " if explanation else "") + \
                "(Downgraded to unknown: the cited text could not be verified in the repository.)"
        out.append({
            "question": a["question"],
            "answer": answer,
            "explanation": explanation,
            "citations": kept,
        })
    return out, rejected


def _citation_verifies(citation, snapshot):
    try:
        rel = citation["file"].lstrip("/")
        if len(citation["line_range"]) != 2:
            return False
        start, end = int(citation["line_range"][0]), int(citation["line_range"][1])
        excerpt = citation["excerpt"]
    except (KeyError, TypeError, ValueError, IndexError):
        return False
    lines = snapshot.lines(rel)
    if lines is None or start < 1 or end < start or start > len(lines) or not excerpt.strip():
        return False
    # A little slack around the cited range: models are often one line off
    # on a block's boundaries, and the point is that the words are there.
    window = " ".join(lines[max(start - 2, 0): min(end + 1, len(lines))])
    return _squash(excerpt) in _squash(window)


def _squash(text):
    return " ".join(text.split())


def _unknown(question, explanation):
    return {"question": question, "answer": "unknown", "explanation": explanation, "citations": []}


def _is_arm_template(path):
    """Whether a downloaded .json is an ARM deployment template."""
    try:
        with open(path, encoding="utf-8") as fh:
            return bool(ARM_SCHEMA_RE.search(fh.read()))
    except (OSError, UnicodeDecodeError):
        return False


def _download_snapshot(bucket, prefix, dest_dir):
    """Every file under the prefix with a CONTEXT_SUFFIXES suffix, to
    dest_dir, returned as paths relative to the prefix."""
    paginator = s3.get_paginator("list_objects_v2")
    files = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            admitted = key.endswith(CONTEXT_SUFFIXES)
            arm_candidate = not admitted and key.endswith(".json")
            if not admitted and not arm_candidate:
                continue
            rel = key[len(prefix):]
            local = os.path.join(dest_dir, rel)
            os.makedirs(os.path.dirname(local) or dest_dir, exist_ok=True)
            s3.download_file(bucket, key, local)
            if arm_candidate and not _is_arm_template(local):
                os.remove(local)
                continue
            files.append(rel)
            if len(files) >= MAX_SNAPSHOT_FILES:
                logger.warning("snapshot capped at %d files", MAX_SNAPSHOT_FILES)
                return files
    return files


def _get_anthropic_client():
    global _anthropic_client
    if _anthropic_client is None:
        secret = secretsmanager.get_secret_value(SecretId=ANTHROPIC_SECRET_ARN)
        _anthropic_client = anthropic.Anthropic(api_key=secret["SecretString"])
    return _anthropic_client


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


def _emit_metrics(metrics, dimensions, **context):
    """One Embedded Metric Format line on stdout; same mechanism as
    iac-scanner (observability.tf)."""
    record = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [list(dimensions)],
                "Metrics": [{"Name": name, "Unit": "Count"} for name in metrics],
            }],
        },
        **dimensions, **metrics, **context,
    }
    print(json.dumps(record))
