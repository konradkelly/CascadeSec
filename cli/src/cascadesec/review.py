"""What the review commands say about findings, decided the way the
dashboard decides it (docs/cli-spec.md §10).

The CLI is a third interface onto the same records, and it must not
describe a finding differently from the dashboard. So each rule here is a
port of the dashboard function named beside it, with the same wording, and
nothing here is new judgement. The API keeps the rules that matter: what
this module says about prerequisites is the affordance, and review-api's
409 is the guarantee, exactly as on the dashboard.

  status labels           dashboard/src/components/StatusBadge.tsx
  raw grouping, reasons   dashboard/src/review/unmapped.ts
  self-check verdict      dashboard/src/components/SelfCheckBadge.tsx
  unmet prerequisites     dashboard/src/review/prerequisites.ts
  CDK source line         dashboard/src/review/cdk.ts
"""

import fnmatch
import hashlib

STATUS_LABELS = {
    "raw": "Raw",
    "mapped": "Mapped",
    "fix-proposed": "Fix proposed",
    "needs-human-only": "Needs human",
    "superseded": "Superseded",
    "not-drafted": "Not drafted",
    "resolved": "Resolved",
}
STATUSES = tuple(STATUS_LABELS)

# The findings that have a control, in the order a reviewer works through
# them: what is waiting for a decision, then what has no fix to decide on,
# then what is settled. Raw findings are not here; they are grouped apart.
REVIEW_GROUPS = (
    ("to-review", "Fixes to review", ("fix-proposed", "needs-human-only")),
    ("open", "Open, no fix to review yet", ("mapped", "not-drafted")),
    ("settled", "Settled", ("resolved", "superseded")),
)

SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def severity_rank(severity):
    """Worst first; unknown or absent sorts after LOW rather than being dropped."""
    return _SEVERITY_RANK.get((severity or "").lower(), len(SEVERITIES))


# ---------- raw findings (unmapped.ts) ----------

REASON_ORDER = ("unreviewed", "not-examined", "no-control", "not-fixable", "hygiene")

REASON_LABELS = {
    "unreviewed": "Not yet reviewed",
    "not-examined": "Not examined",
    "no-control": "No control in the loaded frameworks",
    "not-fixable": "Cannot be fixed in the file",
    "hygiene": "Hygiene, not a security control",
}

REASON_DESCRIPTIONS = {
    "unreviewed":
        "Nobody has judged these rules yet. Each is either a mapping waiting to be written or "
        "a decision to record in the corpus; this is the only group that is a backlog.",
    "not-examined":
        "The mapping stage has not settled these: they are outside the files this PR changed, "
        "their mapping failed and will be retried on the next run, or they were scanned before "
        "unmapped findings were tagged.",
    "no-control":
        "Real advice, but no loaded framework has a control these violate. Mapping them anyway "
        "would cite a control for something it does not say. Loading a framework that covers them "
        "is what moves them.",
    "not-fixable":
        "No edit to the file can clear these with the current scanners, so a fix would be drafted, "
        "fail its self-check and be drafted again on every run.",
    "hygiene": "Conventions and tidiness, such as names and descriptions, rather than exposure.",
}


def is_unmapped(finding):
    return finding.get("status") == "raw"


def unmapped_reason(finding):
    """A raw finding with no tag was never examined -- not judged."""
    return finding.get("unmapped_reason") or "not-examined"


def group_unmapped(findings):
    """[{reason, finding_count, rules: [{key, source, rule_id, title, severity,
    file_count, findings}]}], in REASON_ORDER, rules worst severity first and
    then by how many findings they carry. One row per rule: a hundred
    findings of one rule are one decision, not a hundred."""
    by_reason = {}
    for f in findings:
        if not is_unmapped(f):
            continue
        rules = by_reason.setdefault(unmapped_reason(f), {})
        rules.setdefault(f"{f['source']}:{f['rule_id']}", []).append(f)

    groups = []
    for reason in [r for r in REASON_ORDER if r in by_reason] + sorted(set(by_reason) - set(REASON_ORDER)):
        rules = []
        for key, fs in by_reason[reason].items():
            worst = min(fs, key=lambda f: severity_rank(f.get("severity")))
            rules.append({
                "key": key,
                "source": fs[0]["source"],
                "rule_id": fs[0]["rule_id"],
                "title": next((f["title"] for f in fs if f.get("title")), None),
                "severity": worst.get("severity"),
                "file_count": len({f["file"] for f in fs}),
                "findings": sorted(fs, key=lambda f: f["file"]),
            })
        rules.sort(key=lambda r: (severity_rank(r["severity"]), -len(r["findings"]), r["key"]))
        groups.append({"reason": reason, "finding_count": sum(len(r["findings"]) for r in rules),
                       "rules": rules})
    return groups


def mapped_share(findings):
    """Share of findings with a control; None for no findings, so a clean PR
    does not read as 0%."""
    if not findings:
        return None
    return sum(1 for f in findings if not is_unmapped(f)) / len(findings)


# ---------- the self-check (SelfCheckBadge.tsx) ----------

def human_gates(fix):
    """Why a fix whose rescan came back clean is still held: remediation-agent
    records those as self_check_passed=false with cleared=true and nothing
    new, which must not read as a fix the scanner rejected."""
    if (not fix or fix.get("self_check_passed") is not False or fix.get("cleared") is not True
            or fix.get("self_check_new_findings") or fix.get("scan_errors")
            or fix.get("suppression_attempt")):
        return []
    gates = []
    if fix.get("dropped_resources"):
        gates.append("deletes a resource")
    if fix.get("assumptions"):
        gates.append("rests on assumptions")
    if any(q.get("answer") == "unknown" for q in fix.get("questions") or []):
        gates.append("asked the repository something it could not answer")
    return gates


def self_check(fix):
    """(verdict, detail or None). The verdict is the dashboard badge's text."""
    if not fix or "self_check_passed" not in fix or fix.get("self_check_passed") is None:
        return "No self-check", None
    if fix["self_check_passed"]:
        return "Self-check passed", None
    gates = human_gates(fix)
    if gates:
        return ("Rescan clean, held for review",
                "the rescan cleared the finding and introduced nothing; held because the fix "
                + " and ".join(gates))
    # Read before cleared/new: a parse failure has the same shape as a miss.
    if fix.get("scan_errors"):
        return "Fix did not parse", "the scanner could not parse the fix, so nothing was verified"
    new = len(fix.get("self_check_new_findings") or [])
    reasons = []
    if fix.get("cleared") is False or ("cleared" not in fix and new == 0):
        reasons.append("original issue not cleared")
    if new:
        reasons.append(f"{new} new finding{'' if new == 1 else 's'} introduced")
    return "Self-check failed", "; ".join(reasons) or "original issue not cleared"


# ---------- the chain (prerequisites.ts) ----------

UNMET_EXPLANATION = {
    "missing": "no longer exists",
    "unresolved": "has not been accepted yet",
    "stale": "was edited after this fix was drafted on it",
    "unverifiable": "was recorded without a hash, so it cannot be checked",
    # review-api's 409 can say more than the local check, because it reads
    # the prerequisite's event log (_unmet_prerequisites): where this side
    # can only say `unresolved`, the server says which.
    "undecided": "has no decision yet",
    "rejected": "was rejected, so the content this fix was drafted on is never landing",
    "reopened": "was reopened by the system and is waiting to be redrafted",
}


def diff_sha256(diff_text):
    """Must match remediation-agent's and review-api's _diff_sha256."""
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


def normalize_prerequisite(entry):
    """Entries were bare id strings before the chain carried hashes."""
    return {"finding_id": entry} if isinstance(entry, str) else entry


def unmet_prerequisites(chain, by_id):
    """[{finding_id, reason}] for the prerequisites that block accepting this
    fix. The weaker check of the two, as on the dashboard: with statuses but
    no event logs, a rejection and a decision never made both read
    `unresolved`. review-api's 409 says which."""
    unmet = []
    for entry in map(normalize_prerequisite, chain or []):
        fid = entry["finding_id"]
        prerequisite = by_id.get(fid)
        if prerequisite is None:
            unmet.append({"finding_id": fid, "reason": "missing"})
        elif prerequisite.get("status") != "resolved":
            unmet.append({"finding_id": fid, "reason": "unresolved"})
        elif not entry.get("diff_sha256"):
            unmet.append({"finding_id": fid, "reason": "unverifiable"})
        else:
            diff = (prerequisite.get("proposed_fix") or {}).get("diff")
            if diff is None or diff_sha256(diff) != entry["diff_sha256"]:
                unmet.append({"finding_id": fid, "reason": "stale"})
    return unmet


# ---------- where a finding is (cdk.ts) ----------

CDK_EXPLAINER = (
    "Found in a template synthesized from a CDK app. Its fix is drafted in the app's source, "
    "the file that made the resource, and verified by synthesizing the app again and rescanning."
)


def cdk_source(finding):
    """`lib/network.ts:8`, or None when the app's metadata named no line."""
    origin = finding.get("origin") or {}
    if finding.get("target_type") != "cdk" or not origin.get("file") or origin.get("line") is None:
        return None
    return f"{origin['file']}:{origin['line']}"


def location(finding):
    """Where a person goes to look. A synthesized template's lines mean
    nothing to its author; the source line does."""
    source = cdk_source(finding)
    if source:
        return source
    start, end = (list(finding.get("line_range") or []) + [None, None])[:2]
    if start is not None and end is not None and start != end:
        return f"{finding['file']}:{start}-{end}"
    if start is not None:
        return f"{finding['file']}:{start}"
    return finding["file"]


# ---------- filters for `findings` ----------

def matches_file(finding, pattern):
    """A glob when it has one, else the exact path or anything under it as a
    directory. Checked against the source line's file too, for CDK."""
    paths = {finding.get("file") or ""}
    origin_file = (finding.get("origin") or {}).get("file")
    if origin_file:
        paths.add(origin_file)
    pattern = pattern.replace("\\", "/").rstrip("/")
    if any(ch in pattern for ch in "*?["):
        return any(fnmatch.fnmatchcase(p, pattern) for p in paths)
    return any(p == pattern or p.startswith(pattern + "/") for p in paths)


def filter_findings(findings, statuses=None, min_severity=None, file=None):
    """--status (any of), --severity (at or above), --file."""
    kept = findings
    if statuses:
        kept = [f for f in kept if f.get("status") in statuses]
    if min_severity:
        floor = _SEVERITY_RANK[min_severity]
        kept = [f for f in kept if severity_rank(f.get("severity")) <= floor]
    if file:
        kept = [f for f in kept if matches_file(f, file)]
    return kept


def sort_key(finding):
    return (severity_rank(finding.get("severity")), finding.get("rule_id", ""), location(finding))
