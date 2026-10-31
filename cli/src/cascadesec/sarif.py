"""SARIF 2.1.0 for a scan's result (docs/sarif-spec.md): findings in, one
document out, no I/O. `cascadesec scan --format sarif` is the caller, so
GitHub Code Scanning, Azure DevOps, GitLab and SARIF viewers can show
CascadeSec's findings with no integration code of their own.

Local mode only, for now: a finding carries the controls a remote scan would
choose among (`candidate_controls`), never a citation, and no fix. A remote
scan's cited controls and verified fixes come with remote mode (cli-spec §4).

What it does not do, on purpose:
  - Drop what the scan could not read. A file that did not parse, or an app
    that was not run, is an error notification, and the run's
    executionSuccessful is false: a consumer reading only `results` would
    otherwise show a clean run (integrations-spec §2.2).
  - Omit baselined findings. They are emitted as suppressed, with the
    baseline file as the justification (§4): a suppression that is visible
    can be reviewed, an omitted one cannot.
  - Carry model prose. Local mode has none, and remote mode's rationale and
    assumptions never enter SARIF, because the file goes where anyone who
    can read the repository reads it (integrations-spec §2.3).

GitHub's rules, from its SARIF documentation (read 2026-10-31):
  - It tracks an alert across runs by `partialFingerprints`, and only by
    the `primaryLocationLineHash` key. Without one, upload-sarif computes a
    hash of the flagged line's text, and the REST upload computes nothing.
    So the S2 fingerprint goes in that key as well as under its own name:
    it does not change when lines move, which is the reason it exists
    (integrations-spec §3.2).
  - security-severity over 9.0 is critical, 7.0-8.9 high, 4.0-6.9 medium,
    0.1-3.9 low; a rule without one is ranked by its results' `level`.
  - A rule's descriptions and help must be non-empty, and the descriptions
    at most 1024 characters.
  - A file over any of its limits is rejected whole, not truncated:
    `over_limits` names the ones a scan can reach.
"""

import gzip
import json
import re
from collections import Counter, defaultdict
from urllib.parse import quote

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
INFORMATION_URI = "https://github.com/konradkelly/CascadeSec"

# sarif-spec D1. Each sits inside GitHub's band for the severity it names.
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

MAX_TEXT = 1024
MAX_TAGS = 20
MAX_RESULTS = 25_000
MAX_RULES = 25_000
MAX_GZIP_BYTES = 10 * 1024 * 1024

# A `resource` that names nothing: a placeholder (KICS's `n/a`), or a
# position (Trivy names a CloudFormation resource `template.yaml:5-8`), which
# the location already gives and which goes stale when lines move. The same
# test as the scanner's fingerprint (iac-scanner _anchor_resource).
POSITIONAL_RESOURCE_RE = re.compile(r"(^|:)\d+(\s*-\s*\d+)?$")
PLACEHOLDER_RESOURCES = {"n/a", "unknown", "none"}

# The four reasons a finding has no candidate control, in the words the
# dashboard and `cascadesec findings` use for them.
RAW_REASONS = {
    "no-control": "no control in the corpus covers this rule",
    "hygiene": "a hygiene rule, not a control failure",
    "not-fixable": "not something a change to the file can fix",
    "unreviewed": "not reviewed for the corpus yet",
}


def document(summary, baselined, version, root=""):
    """The SARIF document for a scan.

    summary    `cascadesec scan`'s result: findings after the baseline,
               scan_errors, unscanned_apps, skipped_apps, scanner_image
    baselined  the findings the baseline left out of the verdict
    version    this CLI's version
    root       the scanned directory's path from the repository root
               (`infra/`), since a SARIF consumer reads paths from there;
               empty for the root itself or outside a repository
    """
    findings = [(f, False) for f in summary.get("findings") or []]
    findings += [(f, True) for f in baselined or []]
    findings.sort(key=lambda pair: _order(pair[0]))

    rules = _rules([f for f, _ in findings])
    index = {rule["id"]: i for i, rule in enumerate(rules)}
    seen = Counter()
    results = []
    for f, suppressed in findings:
        seen[f.get("fingerprint")] += 1
        results.append(_result(f, index, root, seen[f.get("fingerprint")],
                               summary.get("baseline") if suppressed else None))

    notifications = _notifications(summary, root)
    run = {
        "tool": {"driver": {
            "name": "CascadeSec",
            "version": version,
            "informationUri": INFORMATION_URI,
            "rules": rules,
            "properties": {"scannerImage": summary.get("scanner_image")},
        }},
        "invocations": [{
            # An app not run or a file not parsed is a scan that did not
            # happen, whatever --allow-scan-errors did to the exit code.
            "executionSuccessful": not (summary.get("scan_errors") or summary.get("unscanned_apps")),
            "toolExecutionNotifications": notifications,
        }],
        "results": results,
    }
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def over_limits(document_, text):
    """What GitHub would reject this file for, as sentences; empty when it
    would take it. `text` is the document as it will be written."""
    run = document_["runs"][0]
    problems = []
    if len(run["results"]) > MAX_RESULTS:
        problems.append(f"{len(run['results'])} results, over the {MAX_RESULTS} a run may hold")
    if len(run["tool"]["driver"]["rules"]) > MAX_RULES:
        problems.append(f"{len(run['tool']['driver']['rules'])} rules, over the {MAX_RULES} a run may hold")
    size = len(gzip.compress(text.encode("utf-8")))
    if size > MAX_GZIP_BYTES:
        problems.append(f"{size / 1024 / 1024:.1f} MB gzipped, over the 10 MB upload limit")
    return problems


def rule_id(f):
    # Prefixed: rule ids collide across tools, and a KICS id is a bare UUID.
    return f"{f.get('source')}:{f.get('rule_id')}"


def _order(f):
    start = _lines(f)[0]
    return (f.get("file") or "", start or 0, rule_id(f), f.get("fingerprint") or "")


def _lines(f):
    """(start, end) when the finding names lines, else (None, None): a
    whole-file finding gets no region rather than an invented one."""
    line_range = list(f.get("line_range") or []) + [None, None]
    start, end = line_range[0], line_range[1]
    if not isinstance(start, int) or start < 1:
        return None, None
    return start, end if isinstance(end, int) and end >= start else None


def _controls(f):
    return [f"{c['framework']}/{c['control_id']}" for c in f.get("candidates") or []]


def _rules(findings):
    by_id = {}
    controls = defaultdict(dict)        # ordered, de-duplicated
    titles = {}
    for f in findings:
        rid = rule_id(f)
        by_id.setdefault(rid, f)
        for c in f.get("candidates") or []:
            key = f"{c['framework']}/{c['control_id']}"
            controls[rid][key] = None
            titles[key] = c.get("title")
    rules = []
    for rid in sorted(by_id):
        f = by_id[rid]
        title = f.get("title") or rid
        # checkov reports a name and no prose, so its description is empty.
        description = f.get("description") or title
        cited = list(controls[rid])
        tags = list(dict.fromkeys(["security", f.get("target_type") or "iac", *cited]))[:MAX_TAGS]
        rule = {
            "id": rid,
            "shortDescription": {"text": _clip(title)},
            "fullDescription": {"text": _clip(description)},
            "help": {"text": _help(description, cited, titles, f.get("raw_reason"))},
            "properties": {"tags": tags},
        }
        severity = (f.get("severity") or "").upper()
        if severity in SECURITY_SEVERITY:
            rule["properties"]["security-severity"] = SECURITY_SEVERITY[severity]
        rules.append(rule)
    return rules


def _help(description, controls, titles, raw_reason):
    if controls:
        lines = [f"- {c}" + (f": {titles[c]}" if titles.get(c) else "") for c in controls]
        return (f"{description}\n\nCandidate controls -- the ones a remote CascadeSec scan chooses "
                "among and cites; a local scan does not choose:\n" + "\n".join(lines))
    reason = RAW_REASONS.get(raw_reason or "unreviewed", raw_reason)
    return f"{description}\n\nNo candidate control: {reason}."


def _result(f, index, root, occurrence, baseline_file):
    rid = rule_id(f)
    title = f.get("title") or rid
    resource = f.get("resource") or ""
    location = {"artifactLocation": {"uri": _uri(root, f.get("file") or ""), "uriBaseId": "%SRCROOT%"}}
    start, end = _lines(f)
    if start is not None:
        location["region"] = {"startLine": start, **({"endLine": end} if end else {})}
    severity = (f.get("severity") or "").upper()
    result = {
        "ruleId": rid,
        "ruleIndex": index[rid],
        "level": LEVEL.get(severity, "note"),
        "message": {"text": f"{title} ({resource})" if _names(resource) else title},
        "locations": [{"physicalLocation": location}],
    }
    fingerprint = f.get("fingerprint")
    if fingerprint:
        # The occurrence count keeps apart two findings that share a
        # fingerprint (one rule, one resource, two lines of it), as
        # upload-sarif's own line hashes do. Results are sorted by line, so
        # the count does not change when both move.
        result["partialFingerprints"] = {"cascadesec/v1": fingerprint,
                                         "primaryLocationLineHash": f"{fingerprint}:{occurrence}"}
    properties = {"finding_id": f.get("finding_id"), "severity": severity or None,
                  "target_type": f.get("target_type"), "candidate_controls": _controls(f)}
    if f.get("raw_reason"):
        properties["raw_reason"] = f["raw_reason"]
    if f.get("detection_only"):
        properties["detection_only"] = True
    result["properties"] = properties
    if baseline_file:
        result["baselineState"] = "unchanged"
        result["suppressions"] = [{"kind": "external", "status": "accepted",
                                   "justification": f"in {baseline_file}"}]
    return result


def _names(resource):
    return bool(resource) and resource.lower() not in PLACEHOLDER_RESOURCES \
        and not POSITIONAL_RESOURCE_RE.search(resource)


def _notifications(summary, root):
    notes = []
    for path in summary.get("scan_errors") or []:
        notes.append(_note("error", "scan-error", f"{path} could not be parsed, so it was not scanned.",
                           _uri(root, path)))
    for app in summary.get("unscanned_apps") or []:
        notes.append(_note("error", "app-not-run",
                           f"{app.get('kind')} app at {app.get('path')} was not run, so the IaC it "
                           f"generates was not scanned: {app.get('reason')}", _uri(root, app.get("path"))))
    for app in summary.get("skipped_apps") or []:
        notes.append(_note("note", "app-skipped",
                           f"{app.get('kind')} app at {app.get('path')} is skipped by {app.get('source')}: "
                           f"{app.get('reason')}", _uri(root, app.get("path"))))
    return notes


def _note(level, descriptor, text, uri):
    return {"level": level, "descriptor": {"id": descriptor}, "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}}]}


def _uri(root, path):
    """A repository-relative URI reference: forward slashes, and anything a
    URI cannot hold as-is (a space, `#`, `%`) percent-encoded."""
    path = (path or "").replace("\\", "/").strip("/")
    path = "" if path == "." else path
    joined = f"{root.strip('/')}/{path}".strip("/") if root.strip("/") else path
    return quote(joined or ".", safe="/")


def _clip(text):
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 3] + "..."


def dumps(document_):
    return json.dumps(document_, indent=2) + "\n"
