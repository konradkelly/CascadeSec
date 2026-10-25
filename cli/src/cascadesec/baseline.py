"""What a local scan holds back from its verdict, and says so
(docs/cli-spec.md §3.5, §6): the baseline, --changed-only and skip_apps.

PugetScope carries 566 findings; a gate that fails on all of them is turned
off on day one. Each of these narrows what counts, and none of them is
silent -- every finding left out is counted in the output, and the reason
it was left out is in a file someone reviewed or a flag someone passed.

  baseline       .cascadesec-baseline.json, committed: the findings a team
                 has accepted for now, keyed on the S2 fingerprint so they
                 stay accepted when lines move
  --changed-only only what is in files changed since REV, which is the
                 check run's added-lines approximation and has its limit:
                 a change can make an untouched file newly vulnerable
  skip_apps      apps local mode cannot run, which a team chose not to be
                 told about, each with a reason
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from cascadesec.errors import USAGE, CliError

FILE = ".cascadesec-baseline.json"
VERSION = 1


# ---------- the file ----------

def default_path(scan_path):
    return Path(scan_path) / FILE


def entries_for(findings):
    """One entry per fingerprint, in an order that diffs well. Two findings
    can share a fingerprint (one rule, one resource, two lines of it); one
    entry covers both, which is the limit integrations-spec §3.2 accepts."""
    by_fp = {}
    for f in findings:
        fp = f.get("fingerprint")
        if not fp or fp in by_fp:
            continue
        by_fp[fp] = {
            "fingerprint": fp,
            "source": f["source"],
            "rule_id": f["rule_id"],
            "file": f["file"],
            "line": (f.get("line_range") or [None])[0],
            "severity": f.get("severity"),
            "title": f.get("title") or "",
        }
    return sorted(by_fp.values(), key=lambda e: (e["file"], e["rule_id"], e["fingerprint"]))


def write(path, entries, scanner_image):
    document = {
        "version": VERSION,
        # Readers: what this file is, for whoever meets it in a diff.
        "about": "Findings this repository has accepted for now. `cascadesec scan` leaves these "
                 "out of its verdict and says how many; remove an entry to gate on it again.",
        "scanner_image": scanner_image,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "findings": entries,
    }
    Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")


def load(path):
    """The baseline document, or None when there is no file."""
    path = Path(path)
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise CliError(f"{path}: not a baseline ({e})", USAGE) from None
    if (not isinstance(document, dict) or document.get("version") != VERSION
            or not isinstance(document.get("findings"), list)
            or not all(isinstance(e, dict) and isinstance(e.get("fingerprint"), str)
                       for e in document["findings"])):
        raise CliError(f"{path}: not a version-{VERSION} baseline; write one with `cascadesec baseline`",
                       USAGE)
    return document


# ---------- applying it ----------

def apply(findings, document):
    """(kept, suppressed, fixed): findings the baseline does not cover, the
    ones it does, and baseline entries nothing fired for -- fixed, or the
    rule stopped matching, and either way ready to remove."""
    if document is None:
        return list(findings), [], []
    accepted = {e["fingerprint"]: e for e in document["findings"]}
    kept = [f for f in findings if f.get("fingerprint") not in accepted]
    suppressed = [f for f in findings if f.get("fingerprint") in accepted]
    fired = {f.get("fingerprint") for f in findings}
    fixed = [e for fp, e in accepted.items() if fp not in fired]
    return kept, suppressed, fixed


def prune(document, findings):
    """The baseline with only the entries that still fire. Adds nothing: a
    new finding goes into the baseline only by writing it again, which is
    a decision someone makes, not a side effect of tidying."""
    fired = {f.get("fingerprint") for f in findings}
    return [e for e in document["findings"] if e["fingerprint"] in fired]


# ---------- --changed-only ----------

def changed_files(scan_path, rev, run=subprocess.run):
    """Paths, relative to `scan_path`, that differ from `rev` or are new and
    untracked. `--relative` makes git answer in the scan's own terms, so a
    scan of a subdirectory compares like with like."""
    def git(*args):
        result = run(["git", "-C", str(scan_path), *args], capture_output=True, text=True)
        if result.returncode != 0:
            raise CliError(f"--changed-only {rev}: git said: {(result.stderr or '').strip()}", USAGE)
        return [line for line in result.stdout.splitlines() if line.strip()]

    return set(git("diff", "--name-only", "--relative", rev, "--")) | set(
        git("ls-files", "--others", "--exclude-standard"))


def _in_changed(path, changed):
    return path in changed


def _app_touched(app_path, changed):
    if app_path in (".", ""):
        return bool(changed)
    prefix = app_path.rstrip("/") + "/"
    return any(c.startswith(prefix) for c in changed)


def scope_to_changes(result, changed):
    """The result with only what lies in changed files: findings and parse
    errors in them (a CDK finding counts by its source line's file), and
    apps with a changed file inside. (scoped result, findings left out)."""
    def touched(f):
        origin_file = (f.get("origin") or {}).get("file")
        return f.get("file") in changed or (origin_file is not None and origin_file in changed)

    findings = result.get("findings") or []
    kept = [f for f in findings if touched(f)]
    return {
        **result,
        "findings": kept,
        "scan_errors": [e for e in result.get("scan_errors") or [] if _in_changed(e, changed)],
        "unscanned_apps": [a for a in result.get("unscanned_apps") or [] if _app_touched(a["path"], changed)],
    }, len(findings) - len(kept)


def introduced(result, earlier_findings, in_change=None):
    """(result with only the findings the change brought, how many were
    already there, how many lie in files outside the change). Brought means
    the earlier version's scan has no finding with that fingerprint
    (history.py). `in_change`, when given, is the files the change's own
    version holds; a finding in any other file -- an untracked file beside a
    changed one -- is outside it. Two findings that share a fingerprint are
    one, as in the baseline: a second line of one resource tripping the
    same rule reads as already there."""
    before = {f.get("fingerprint") for f in earlier_findings}
    findings = result.get("findings") or []
    held = [f for f in findings if in_change is None or f.get("file") in in_change]
    new = [f for f in held if f.get("fingerprint") not in before]
    return {**result, "findings": new}, len(held) - len(new), len(findings) - len(held)


# ---------- skip_apps ----------

def skip_apps(result, scan_path, skips):
    """(result without the skipped apps, [{path, kind, reason}] skipped).
    A skip names an app by its path from the .cascadesec.toml that declared
    it; an app is reported by its path from the scan root."""
    if not skips:
        return result, []
    root = Path(scan_path).resolve()
    skipped_by = {s["path"]: s for s in skips}
    kept, skipped = [], []
    for app in result.get("unscanned_apps") or []:
        where = (root / PurePosixPath(app["path"])).resolve()
        skip = skipped_by.get(where)
        if skip:
            skipped.append({**app, "reason": skip["reason"], "source": skip["source"]})
        else:
            kept.append(app)
    return {**result, "unscanned_apps": kept}, skipped


def same_image(document, image_ref):
    return document is None or document.get("scanner_image") in (None, image_ref)


def relative_to_cwd(path):
    try:
        return os.path.relpath(path)
    except ValueError:      # another drive, on Windows
        return str(path)
