#!/usr/bin/env python3
"""Fix quality (docs/completion.md phase 2 step 2), from pipeline runs.

  python run_fix_eval.py --run fixeval-cases-1=cases
  python run_fix_eval.py --run sub-1=DIR --run sub-2=DIR --run sub-3=DIR --report out.json
  python run_fix_eval.py ... --audit-sample 45 --audit-out fix_audit.json

Each --run names a pipeline run and the directory it scanned, so a fix's
file can be rebuilt from the original. The runs are made beforehand,
against the deployed stack, as scripts/scan.py makes them:

  python scripts/scan.py corpus/eval/cases --pr-id fixeval-cases-1 --yes

Recorded per fix, mechanically, from what remediation-agent wrote:

  outcome     passed (a reviewer would see a clean fix), held, superseded
              (another fix on the resource cleared it first), or not drafted.
  gates       every reason a fix was held, in the order the handler checks
              them: suppression, scan error, not cleared, introduced a
              finding, deleted a resource, assumption, unanswered question.
              The first is the gate that held it.
  diff size   lines added plus removed; whether the rationale was empty.
  validity    `terraform validate` on the file with the fix's chain applied,
              against the original's verdict, so a case that never validated
              (a remote module, a placeholder) is not charged to the fix.
              Other languages are recorded as not checked: no validator for
              them is installed here, and phase 4 decides whether to gate.
  cost        tokens and dollars from the agents' usage log lines:
              remediation by finding id, context-agent by the run's window,
              since its lines carry no run id. Runs must not overlap.

Across runs of the same directory, per finding: how many drafts passed, and
whether the passing drafts make the same change.

--audit-sample draws fixes for the human audit, stratified by language and
by passed or held, and writes them with an empty verdict for each.
"""

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]

# $ per million tokens, in / out. claude-api skill, cached 2026-11-03.
PRICES = {
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
}
PASSED, HELD, SUPERSEDED, NOT_DRAFTED = "passed", "held", "superseded", "not drafted"
GATES = ("suppression", "scan error", "not cleared", "introduced a finding",
         "deleted a resource", "assumption", "unanswered question")
TERRAFORM = ("terraform",)


# ---------------------------------------------------------------- per fix

def outcome(item):
    status = item.get("status")
    if status == "superseded":
        return SUPERSEDED
    # not-drafted is the handler's own word for a finding past the file's
    # draft budget (not_drafted_reason says so); the next run picks it up.
    if status == "not-drafted" or not item.get("proposed_fix"):
        return NOT_DRAFTED
    return PASSED if status == "fix-proposed" else HELD


def gates(fix):
    """Every gate the fix tripped, in the handler's order (remediation-agent
    _remediate_one): suppression and scan errors return before the verdict;
    the rest are evaluated after the rescan."""
    out = []
    if fix.get("suppression_attempt"):
        out.append("suppression")
    if fix.get("scan_errors"):
        out.append("scan error")
    if not (fix.get("suppression_attempt") or fix.get("scan_errors")):
        if not fix.get("cleared"):
            out.append("not cleared")
        if fix.get("self_check_new_findings"):
            out.append("introduced a finding")
    if fix.get("dropped_resources"):
        out.append("deleted a resource")
    if fix.get("assumptions"):
        out.append("assumption")
    if any(q.get("answer") == "unknown" for q in fix.get("questions") or []):
        out.append("unanswered question")
    return out


def changed_lines(diff):
    return [l for l in (diff or "").splitlines()
            if l[:1] in "+-" and not l.startswith(("+++", "---"))]


def change_key(diff):
    """What a draft changes, whitespace aside, so two drafts that make the
    same edit compare equal even when their hunks are aligned differently."""
    removed = sorted(" ".join(l[1:].split()) for l in changed_lines(diff) if l[0] == "-")
    added = sorted(" ".join(l[1:].split()) for l in changed_lines(diff) if l[0] == "+")
    return hashlib.sha256(json.dumps([removed, added]).encode()).hexdigest()[:12]


def language(item):
    return item.get("target_type") or "terraform"


def row(item):
    fix = item.get("proposed_fix") or {}
    g = gates(fix) if fix else []
    return {
        "finding_id": item["finding_id"], "file": item["file"], "language": language(item),
        "rule": f'{item["source"]}:{item["rule_id"]}', "resource": item.get("resource", ""),
        "outcome": outcome(item), "gates": g, "held_by": g[0] if g and outcome(item) == HELD else None,
        "new_findings": list(fix.get("self_check_new_findings") or []),
        "diff_lines": len(changed_lines(fix.get("diff"))),
        "no_rationale": bool(fix.get("rationale_missing")),
        "questions": len(fix.get("questions") or []),
        "change": change_key(fix.get("diff")) if fix.get("diff") else None,
        "applies_after": [a["finding_id"] for a in fix.get("applies_after") or []],
        "diff": fix.get("diff") or "", "rationale": fix.get("rationale") or "",
        "assumptions": list(fix.get("assumptions") or []),
    }


# ---------------------------------------------------------------- validity

def corrected(r, by_id, source_dir, workdir):
    """Write the fix's file as it would be after its chain and itself are
    applied to the original, under workdir. Returns the path, or None when a
    diff in the chain does not apply."""
    target = workdir / r["file"]
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_dir / r["file"], target)
    for fid in r["applies_after"] + [r["finding_id"]]:
        diff = by_id[fid]["diff"] if fid in by_id else None
        if not diff:
            return None
        # -F0: no fuzz. A diff whose context does not match exactly is a chain
        # out of order, and a fuzzy apply would validate a file nobody wrote.
        p = subprocess.run(["patch", "-p1", "-F0", "--forward", "--no-backup-if-mismatch", "-s",
                            "-d", str(workdir)],
                           input=diff, capture_output=True, text=True)
        if p.returncode:
            return None
    return target


_validated = {}
# One working directory for every validation, so the AWS provider (~735 MB)
# is installed once. A fresh `terraform init` per case copies it each time
# on Windows, where the plugin cache cannot symlink, and on 2026-11-22 two
# such copies filled the disk.
WORKSPACE = pathlib.Path(tempfile.gettempdir()) / "fixeval-tf-workspace"


def terraform_valid(case_dir):
    """`terraform validate` on one directory's files; cached by their contents."""
    files = sorted(p for p in case_dir.iterdir() if p.is_file())
    key = hashlib.sha256(b"".join(p.name.encode() + p.read_bytes() for p in files)).hexdigest()
    if key not in _validated:
        WORKSPACE.mkdir(exist_ok=True)
        for p in WORKSPACE.iterdir():
            if p.is_file() and p.name != ".terraform.lock.hcl":
                p.unlink()
        for p in files:
            shutil.copyfile(p, WORKSPACE / p.name)
        env = dict(os.environ, TF_IN_AUTOMATION="1")
        # Re-run each time for the case's modules; providers already in
        # .terraform at the locked version are not installed again.
        init = subprocess.run(["terraform", "init", "-backend=false", "-input=false", "-no-color"],
                              cwd=WORKSPACE, capture_output=True, text=True, env=env)
        if init.returncode:
            _validated[key] = False
        else:
            v = subprocess.run(["terraform", "validate", "-json", "-no-color"],
                               cwd=WORKSPACE, capture_output=True, text=True, env=env)
            _validated[key] = json.loads(v.stdout or "{}").get("valid", False)
    return _validated[key]


def validity(rows, source_dir):
    """Set r["valid"] on each drafted fix: True, False, "original invalid",
    "no change", "chain does not apply", or "not checked"."""
    by_id = {r["finding_id"]: r for r in rows}
    for r in rows:
        if r["outcome"] not in (PASSED, HELD):
            continue
        if r["language"] not in TERRAFORM:
            r["valid"] = "not checked"
            continue
        with tempfile.TemporaryDirectory() as orig, tempfile.TemporaryDirectory() as fixed:
            orig, fixed = pathlib.Path(orig), pathlib.Path(fixed)
            case = pathlib.Path(r["file"]).parent
            for root in (orig, fixed):
                shutil.copytree(source_dir / case, root / case, dirs_exist_ok=True)
            if not terraform_valid(orig / case):
                r["valid"] = "original invalid"
                continue
            # A fix that returns the file unchanged has nothing to validate.
            if not r["diff"]:
                r["valid"] = "no change"
                continue
            if corrected(r, by_id, source_dir, fixed) is None:
                r["valid"] = "chain does not apply"
                continue
            r["valid"] = terraform_valid(fixed / case)


# ---------------------------------------------------------------- cost

def ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def window(items):
    return (min(ts(i["created_at"]) for i in items), max(ts(i["updated_at"]) for i in items))


def insights(logs, group, query, start, end):
    qid = logs.start_query(logGroupName=group, startTime=int(start.timestamp()) - 60,
                           endTime=int(end.timestamp()) + 60, queryString=query, limit=10000)["queryId"]
    while True:
        r = logs.get_query_results(queryId=qid)
        if r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            return [{f["field"]: f["value"] for f in res} for res in r["results"]]
        time.sleep(1)


def dollars(calls):
    return sum(int(c["tok_in"]) * PRICES[c["model"]][0] / 1e6 + int(c["tok_out"]) * PRICES[c["model"]][1] / 1e6
               for c in calls)


def usage(logs, items, environment="dev"):
    start, end = window(items)
    ids = {i["finding_id"] for i in items}
    q = "fields finding_id, call, model, InputTokens as tok_in, OutputTokens as tok_out | filter ispresent(InputTokens)"
    rem = [c for c in insights(logs, f"/aws/lambda/iacposture-{environment}-remediation-agent", q, start, end)
           if c.get("finding_id") in ids]
    ctx = insights(logs, f"/aws/lambda/iacposture-{environment}-context-agent", q, start, end)
    return {
        "remediation_calls": len(rem), "context_calls": len(ctx),
        "calls_by_kind": dict(collections.Counter(c.get("call") for c in rem)),
        "models": sorted({c["model"] for c in rem}), "context_models": sorted({c["model"] for c in ctx}),
        "tokens_in": sum(int(c["tok_in"]) for c in rem + ctx),
        "tokens_out": sum(int(c["tok_out"]) for c in rem + ctx),
        "remediation_dollars": round(dollars(rem), 4), "context_dollars": round(dollars(ctx), 4),
        "wall_minutes": round((end - start).total_seconds() / 60, 1),
    }


# ---------------------------------------------------------------- runs

def summarize(rows):
    drafted = [r for r in rows if r["outcome"] in (PASSED, HELD)]
    held = [r for r in drafted if r["outcome"] == HELD]
    valid = collections.Counter(str(r.get("valid")) for r in drafted)
    return {
        "findings": len(rows),
        "outcomes": dict(collections.Counter(r["outcome"] for r in rows)),
        "drafted": len(drafted),
        # The first of "what the loop adds": drafts that cleared the finding
        # without adding one, by the self-check's own verdict before the
        # assumption gates. The self-check scans one draft per finding: the
        # first, or the redraft when context-agent answered questions. No
        # draft is redone for failing it, so the redrafted ones are the only
        # place the loop changes what is scanned, and no record says what
        # their first draft would have scored.
        "cleared_cleanly": sum(1 for r in drafted if not ({"not cleared", "introduced a finding",
                                                           "suppression", "scan error"} & set(r["gates"]))),
        "held_by": dict(collections.Counter(r["held_by"] for r in held)),
        "gate_counts": dict(collections.Counter(g for r in drafted for g in r["gates"])),
        "by_language": {lang: dict(collections.Counter(r["outcome"] for r in drafted if r["language"] == lang))
                        for lang in sorted({r["language"] for r in drafted})},
        "validity": dict(valid),
        "no_rationale": sum(1 for r in drafted if r["no_rationale"]),
        "median_diff_lines": sorted(r["diff_lines"] for r in drafted)[len(drafted) // 2] if drafted else 0,
    }


def consistency(runs):
    """Per finding drafted in more than one run of the same directory."""
    per = collections.defaultdict(list)
    for run in runs:
        for r in run["rows"]:
            if r["outcome"] in (PASSED, HELD, SUPERSEDED):
                per[r["finding_id"]].append(r)
    out = []
    for fid, rs in per.items():
        if len(rs) < 2:
            continue
        passing = [r["change"] for r in rs if r["outcome"] == PASSED]
        out.append({"finding_id": fid, "file": rs[0]["file"], "rule": rs[0]["rule"],
                    "runs": len(rs), "passed": len(passing),
                    "outcomes": [r["outcome"] for r in rs],
                    "same_change": len(set(passing)) <= 1 if passing else None})
    return out


def audit_sample(runs, n, seed=20261122):
    """Up to n drafted fixes, stratified by language and passed/held: each
    stratum gets a share in proportion to its size, and at least one."""
    pool = [dict(r, pr_id=run["pr_id"]) for run in runs for r in run["rows"] if r["outcome"] in (PASSED, HELD)]
    strata = collections.defaultdict(list)
    for r in pool:
        strata[(r["language"], r["outcome"])].append(r)
    rng = random.Random(seed)
    take = {k: max(1, round(n * len(v) / len(pool))) for k, v in strata.items()}
    while sum(take.values()) > n:
        biggest = max(take, key=lambda k: take[k])
        take[biggest] -= 1
    picked = []
    for k in sorted(strata):
        picked += rng.sample(strata[k], min(take[k], len(strata[k])))
    return [{"pr_id": r["pr_id"], "finding_id": r["finding_id"], "file": r["file"], "language": r["language"],
             "rule": r["rule"], "outcome": r["outcome"], "gates": r["gates"],
             "verdict": None, "why": ""} for r in picked]


def findings_of(table, pr_id):
    items, kw = [], {"KeyConditionExpression": "pk = :pk AND begins_with(sk, :sk)",
                     "ExpressionAttributeValues": {":pk": f"PR#{pr_id}", ":sk": "FINDING#"}}
    while True:
        page = table.query(**kw)
        items += page["Items"]
        if "LastEvaluatedKey" not in page:
            return [i for i in items if i.get("status") != "raw"]
        kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def score_run(pr_id, source_dir, table, logs, validate=True):
    items = findings_of(table, pr_id)
    rows = [row(i) for i in items]
    if validate:
        validity(rows, source_dir)
    return {"pr_id": pr_id, "source": str(source_dir), "rows": rows,
            "summary": summarize(rows), "usage": usage(logs, items)}


def report(runs, consistent, out=print):
    for run in runs:
        s, u = run["summary"], run["usage"]
        out(f'== {run["pr_id"]}  ({run["source"]})  remediation {",".join(u["models"])}, '
            f'context {",".join(u["context_models"]) or "-"}')
        out(f'   findings {s["findings"]}: ' + ", ".join(f"{k} {v}" for k, v in sorted(s["outcomes"].items())))
        out(f'   drafted {s["drafted"]}: cleared cleanly {s["cleared_cleanly"]}, '
            f'held by {s["held_by"]}, no rationale {s["no_rationale"]}, median diff {s["median_diff_lines"]} lines')
        out(f'   gates tripped {s["gate_counts"]}')
        out(f'   by language {s["by_language"]}')
        out(f'   validity {s["validity"]}')
        out(f'   calls {u["remediation_calls"]} remediation {u["calls_by_kind"]} + {u["context_calls"]} context; '
            f'tokens {u["tokens_in"]:,} in / {u["tokens_out"]:,} out; '
            f'${u["remediation_dollars"] + u["context_dollars"]:.2f} '
            f'(remediation ${u["remediation_dollars"]:.2f}, context ${u["context_dollars"]:.2f}); '
            f'{u["wall_minutes"]} min')
    if consistent:
        k = collections.Counter((c["passed"], c["runs"]) for c in consistent)
        out(f'== across runs: {len(consistent)} findings drafted in 2+ runs; '
            + ", ".join(f"passed {p} of {r}: {n}" for (p, r), n in sorted(k.items())))
        multi = [c for c in consistent if c["passed"] >= 2]
        out(f'   passed in 2+ runs: {len(multi)}, the same change each time: '
            f'{sum(1 for c in multi if c["same_change"])}')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run", action="append", required=True, metavar="PR_ID=DIR",
                    help="a pipeline run and the directory it scanned; repeat")
    ap.add_argument("--report", type=pathlib.Path, help="also write the full result as JSON")
    ap.add_argument("--no-validate", action="store_true", help="skip terraform validate")
    ap.add_argument("--audit-sample", type=int, help="draw this many fixes for the human audit")
    ap.add_argument("--audit-out", type=pathlib.Path, help="where to write the audit sample")
    ap.add_argument("--table", default="iacposture-dev-findings")
    a = ap.parse_args(argv)

    import boto3
    table, logs = boto3.resource("dynamodb").Table(a.table), boto3.client("logs")
    runs = []
    for spec in a.run:
        pr_id, _, d = spec.partition("=")
        runs.append(score_run(pr_id, pathlib.Path(d).resolve(), table, logs, validate=not a.no_validate))
    by_source = collections.defaultdict(list)
    for run in runs:
        by_source[run["source"]].append(run)
    consistent = [c for rs in by_source.values() if len(rs) > 1 for c in consistency(rs)]
    report(runs, consistent)
    if a.report:
        a.report.write_text(json.dumps({"runs": runs, "consistency": consistent}, indent=1, default=str),
                            encoding="utf-8")
    if a.audit_sample:
        sample = audit_sample(runs, a.audit_sample)
        (a.audit_out or HERE / "fix_audit.json").write_text(json.dumps(sample, indent=1) + "\n", encoding="utf-8")
        print(f"audit sample: {len(sample)} fixes")


if __name__ == "__main__":
    sys.exit(main())
