"""The table format of `findings` and `show`: text for a person at a
terminal. `--format json` bypasses all of this and prints what the API
returned, so a script never parses these lines.

Colour is used only on a terminal, and never when NO_COLOR is set
(no-color.org). It marks; it never carries meaning on its own -- every
coloured line says in words what it is.

The CLI's own words are ASCII. A Windows console on a legacy code page
cannot print a middle dot, and a table that crashes on the separator is
worse than one that uses a hyphen. Text from the records (titles,
rationales) can be anything, so main() also has stdout replace what it
cannot encode rather than raise.
"""

import shutil
import textwrap
from datetime import datetime

from cascadesec import review

_RESET = "\033[0m"
_STYLES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}


class Out:
    def __init__(self, stream, color=False):
        self.stream = stream
        self.color = color
        self.width = max(60, min(shutil.get_terminal_size((100, 24)).columns, 120))

    def line(self, text=""):
        self.stream.write(text + "\n")

    def style(self, text, *names):
        if not self.color or not names:
            return text
        return "".join(f"\033[{_STYLES[n]}m" for n in names) + text + _RESET

    def wrap(self, text, indent=2, hang=0, *styles):
        """Fill to the terminal's width. `hang` indents continuation lines
        further, so a wrapped `- item` lines up under its text."""
        prefix = " " * indent
        for paragraph in str(text).splitlines() or [""]:
            if not paragraph.strip():
                self.line()
                continue
            filled = textwrap.fill(paragraph, self.width, initial_indent=prefix,
                                   subsequent_indent=prefix + " " * hang)
            self.line("\n".join(self.style(l, *styles) for l in filled.split("\n")))

    def heading(self, text):
        self.line()
        self.line(self.style(text, "bold"))

    def table(self, headers, rows, indent=2):
        widths = [max(len(str(c)) for c in col) for col in zip(headers, *rows)]
        prefix = " " * indent
        self.line(prefix + self.style("  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip(), "dim"))
        for row in rows:
            self.line(prefix + "  ".join(str(c).ljust(w) for c, w in zip(row, widths)).rstrip())


def _severity(finding_or_severity):
    s = finding_or_severity.get("severity") if isinstance(finding_or_severity, dict) else finding_or_severity
    return (s or "-").upper()


def _rule(finding):
    return f"{finding['source']} {finding['rule_id']}"


def _when(iso):
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


# ---------- findings ----------

def findings(result, out):
    shown = result["findings"]
    total = result["count"]
    share = review.mapped_share(result["all_findings"])
    header = f"{result['pr_id']} - {total} finding{'' if total == 1 else 's'}"
    if share is not None:
        mapped = sum(1 for f in result["all_findings"] if not review.is_unmapped(f))
        header += f" - {mapped} mapped to a control ({round(share * 100)}%)"
    out.line(out.style(header, "bold"))
    if result["filtered"]:
        out.line(out.style(f"{len(shown)} match the filters", "dim"))
    if not shown:
        out.line()
        out.line("No findings match." if result["filtered"] else "No findings.")
        return

    reviewable = [f for f in shown if not review.is_unmapped(f)]
    for _, label, statuses in review.REVIEW_GROUPS:
        group = sorted((f for f in reviewable if f.get("status") in statuses), key=review.sort_key)
        if not group:
            continue
        out.heading(f"{label} ({len(group)})")
        rows = []
        for f in group:
            verdict, _ = review.self_check(f.get("proposed_fix"))
            notes = [verdict] if f.get("proposed_fix") else []
            if f.get("no_longer_detected"):
                notes.append("gone from the code")
            rows.append([f["finding_id"], review.STATUS_LABELS.get(f["status"], f["status"]),
                         _severity(f), _rule(f), review.location(f), ", ".join(notes)])
        out.table(["ID", "STATUS", "SEVERITY", "RULE", "LOCATION", "NOTES"], rows)

    groups = review.group_unmapped(shown)
    if groups:
        raw_total = sum(g["finding_count"] for g in groups)
        out.heading(f"Reported by the scanner, no control mapped ({raw_total})")
        out.wrap("Not hidden, and not review work: nothing is drafted for these. "
                 "One row per rule; --file or --format json for every location.")
        for g in groups:
            label = review.REASON_LABELS.get(g["reason"], g["reason"])
            colour = ("yellow",) if g["reason"] == "unreviewed" else ()
            out.line()
            out.line("  " + out.style(label, "bold", *colour) + out.style(
                f" - {g['finding_count']} finding{'' if g['finding_count'] == 1 else 's'}, "
                f"{len(g['rules'])} rule{'' if len(g['rules']) == 1 else 's'}", "dim"))
            if g["reason"] in review.REASON_DESCRIPTIONS:
                out.wrap(review.REASON_DESCRIPTIONS[g["reason"]], indent=4)
            rows = [[_severity(r["severity"]), f"{r['source']} {r['rule_id']}",
                     f"{len(r['findings'])} in {r['file_count']} file{'' if r['file_count'] == 1 else 's'}",
                     r["title"] or ""] for r in g["rules"]]
            out.table(["SEVERITY", "RULE", "FINDINGS", "TITLE"], rows, indent=4)


# ---------- show ----------

def show(result, out):
    f = result["finding"]
    fix = f.get("proposed_fix") or {}
    verdict, detail = review.self_check(fix) if fix else ("No fix", None)

    # Some scanners put a paragraph in the title (Trivy's AWS-0178 is three
    # sentences), so it is wrapped like prose rather than printed as one line.
    title = f"{f['rule_id']}" + (f" - {f['title']}" if f.get("title") else "")
    out.wrap(title, 0, 2, "bold")
    facts = [
        ("Finding", f["finding_id"]),
        ("PR", result["pr_id"]),
        ("Scanner", f["source"] + (f" ({f['target_type']})" if f.get("target_type") else "")),
        ("Location", review.location(f)),
    ]
    if review.cdk_source(f):
        facts.append(("Synthesized into", f["file"]))
    facts += [
        ("Severity", _severity(f)),
        ("Status", review.STATUS_LABELS.get(f["status"], f["status"])),
        ("Self-check", verdict + (f" ({detail})" if detail else "")),
    ]
    width = max(len(k) for k, _ in facts)
    for key, value in facts:
        out.line(f"  {key:<{width}}  {value}")

    if f.get("target_type") == "cdk":
        out.line()
        out.wrap(review.CDK_EXPLAINER)
    if f.get("no_longer_detected"):
        _alert(out, "The latest scan no longer reports this finding.",
               "Either the fix landed, the code went away, or the rule stopped matching; the "
               "scanner cannot tell which, so it is kept with its history. First absent "
               f"{_when(f['no_longer_detected'])}.")

    out.heading("Control mapping")
    mappings = f.get("control_mappings") or []
    if mappings:
        for m in mappings:
            out.line(f"  {out.style(m['framework'], 'cyan')} {m['control_id']}")
            if m.get("citation_span"):
                out.wrap(f'"{m["citation_span"]}"', indent=4)
            if m.get("rationale"):
                out.wrap(m["rationale"], indent=4)
    elif review.is_unmapped(f):
        reason = review.unmapped_reason(f)
        out.line("  " + review.REASON_LABELS.get(reason, reason))
        if reason in review.REASON_DESCRIPTIONS:
            out.wrap(review.REASON_DESCRIPTIONS[reason], indent=4)
    else:
        out.line("  Not yet mapped to a framework control.")

    if f["status"] == "superseded":
        out.heading("Superseded")
        out.wrap("No fix was drafted for this finding: another fix on the same file already "
                 "cleared the rule it fires on, and the scanner confirmed it no longer reports.")
        if f.get("superseded_by"):
            out.wrap(f"Cleared by {f['superseded_by']}. That fix is still a proposal; if it is "
                     "rejected, this finding comes back and is remediated on its own.")
    if f["status"] == "not-drafted" and f.get("not_drafted_reason"):
        out.heading("Not drafted")
        out.wrap(f["not_drafted_reason"])

    if fix.get("rationale") or fix.get("diff"):
        _fix_sections(result, fix, out)
    elif f["status"] == "needs-human-only":
        out.heading("Proposed fix")
        out.wrap("No diff was drafted for this finding. Review the rationale and address it manually.")

    out.heading("Audit trail")
    events = sorted(result["events"], key=lambda e: e.get("created_at", ""))
    if not events:
        out.line("  No decisions recorded yet.")
    for e in events:
        out.line(f"  {_when(e.get('created_at'))}  {e.get('action', '?'):<9} {e.get('actor', '?')}")
        if e.get("notes"):
            out.wrap(e["notes"], indent=4)


def _fix_sections(result, fix, out):
    out.heading("Remediation rationale")
    if (fix.get("rationale") or "").strip():
        out.wrap(fix["rationale"])
    else:
        out.wrap(out.style("No rationale given: the model returned none with this fix. "
                           "Read the diff below for what it changes.", "dim"))

    if fix.get("suppression_attempt"):
        _alert(out, "This fix tried to silence the scanner, not fix the finding.",
               "It was rejected before being scanned. If the flagged configuration really is "
               "intentional, that is a human decision to record, not one the agent may assert.",
               fix["suppression_attempt"], colour="red")
    if fix.get("stale_reason"):
        _alert(out, "This fix was reopened by the system.", fix["stale_reason"])

    chain = [review.normalize_prerequisite(p) for p in fix.get("applies_after") or []]
    if chain:
        unmet = {u["finding_id"]: u["reason"] for u in result["unmet_prerequisites"]}
        items = [p["finding_id"] + (f" ({review.UNMET_EXPLANATION[unmet[p['finding_id']]]})"
                                    if p["finding_id"] in unmet else "")
                 for p in chain]
        _alert(out, f"This fix is drafted on top of {len(chain)} earlier fix"
               f"{'' if len(chain) == 1 else 'es'} to the same file.",
               "The diff assumes those are already applied; review them first"
               + (f" with `cascadesec show {result['pr_id']} <id>`." if unmet else "."), items)

    if fix.get("scan_errors"):
        _alert(out, "The scanner could not parse this fix, so nothing was verified.",
               "A file that does not parse produces no findings, which looks identical to a "
               "cleared finding. The diff below is unverified.", fix["scan_errors"], colour="red")
    if fix.get("dropped_resources"):
        _alert(out, "This fix deletes infrastructure rather than tightening it.",
               "Removing a resource always satisfies the scanner, but the running system may "
               "depend on it.", fix["dropped_resources"])

    assumptions = fix.get("assumptions") or []
    unanswered = [q for q in fix.get("questions") or [] if q.get("answer") == "unknown"]
    if assumptions or unanswered:
        items = assumptions + [f"Asked, and the repository does not say: {q['question']}"
                               + (f" ({q['explanation']})" if q.get("explanation") else "")
                               for q in unanswered]
        _alert(out, "This fix rests on facts the agent could not check.",
               "Verify each of these before approving:", items)

    if (fix.get("self_check_passed") is False and not fix.get("suppression_attempt")
            and not fix.get("scan_errors") and not review.human_gates(fix)):
        if fix.get("cleared") is False:
            head = "The rescan still reports this finding: the fix did not clear it."
        elif fix.get("cleared") is True:
            head = "The rescan confirmed this finding cleared, but the fix introduced new findings."
        else:
            head = "The scanner did not confirm this fix."
        _alert(out, head, "Do not apply as-is.", fix.get("self_check_new_findings") or [], colour="red")

    answered = [q for q in fix.get("questions") or [] if q.get("answer") != "unknown"]
    if answered:
        out.heading("What the agent checked in the repository")
        for q in answered:
            out.wrap(f"{q['answer'].upper()}: {q['question']}")
            if q.get("explanation"):
                out.wrap(q["explanation"], indent=4)
            for c in q.get("citations") or []:
                lines = c.get("line_range") or []
                where = c["file"] + (f":{lines[0]}-{lines[1]}" if len(lines) == 2 else "")
                out.line("    " + out.style(where, "dim"))

    diff = fix.get("agent_diff") if result.get("agent_diff") else fix.get("diff")
    if diff:
        which = "agent's original" if result.get("agent_diff") else (
            "reviewer's edit" if fix.get("agent_diff") else "")
        out.heading("Proposed diff" + (f" ({which})" if which else ""))
        if fix.get("agent_diff") and not result.get("agent_diff"):
            out.line(out.style("  Edited by a reviewer; --agent-diff shows the agent's original.", "dim"))
        diff_lines(out, diff)


def diff_lines(out, text):
    """A unified diff, coloured on a terminal. The +/- markers carry the
    meaning; colour only makes them quicker to see."""
    for line in text.splitlines():
        if line.startswith(("+++", "---")):
            out.line(out.style(line, "bold"))
        elif line.startswith("+"):
            out.line(out.style(line, "green"))
        elif line.startswith("-"):
            out.line(out.style(line, "red"))
        elif line.startswith("@@"):
            out.line(out.style(line, "cyan"))
        else:
            out.line(line)



# ---------- approve, reject, edit ----------

DONE = {"approved": "Approved", "rejected": "Rejected", "edited": "Recorded your edit of"}


def decision(result, out):
    if not result.get("recorded"):
        out.line("Nothing recorded.")
        return
    action = result["action"]
    out.line(f"{DONE.get(action, action)} the fix for {result['rule']} at {result['location']}"
             f" ({result['finding_id']}).")
    if result.get("status"):
        out.line(f"  Status  {review.STATUS_LABELS.get(result['status'], result['status'])}")
    if action == "edited":
        out.wrap("The edit has not been through the scanner, so its self-check reads as not "
                 "passed until the next scan.")
    reopened = result.get("reopened_dependents") or []
    if reopened:
        out.line()
        out.line(out.style(f"! This reopened {len(reopened)} finding{'' if len(reopened) == 1 else 's'}:",
                           "bold", "yellow"))
        out.wrap("They depended on the fix you just changed: fixes drafted on it go back to "
                 "be redrafted, and findings it superseded go back to mapped.", indent=4)
        for fid in reopened:
            out.line(f"    - {fid}    cascadesec show {result['pr_id']} {fid}")


def _alert(out, headline, body, items=(), colour="yellow"):
    out.line()
    out.line("  " + out.style("! " + headline, "bold", colour))
    out.wrap(body, indent=4)
    for item in items:
        out.wrap(f"- {item}", indent=4, hang=2)
