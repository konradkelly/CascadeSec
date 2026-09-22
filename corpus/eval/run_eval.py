#!/usr/bin/env python3
"""Detection-recall harness for iac-scanner (spec §7.1, §8.2 item 1).

Uploads every case under cases/ to one S3 prefix, invokes the deployed
scanner ONCE with persist=false, and compares what fired against each case's
expected.json. One invocation rather than one per case: the scanner walks
the prefix recursively and Trivy/checkov treat each subdirectory as its own
module, so 37 cases cost one cold start instead of 37.

The deployed function is used rather than local binaries on purpose. Recall
against the tools as actually packaged and versioned in the layer is the
number that matters; a local Trivy of a different version would measure
something else. It also means the harness needs AWS credentials and the
dev stack up.

Usage:
  python run_eval.py                       # bucket from `terraform output`
  python run_eval.py --bucket NAME --function NAME
  python run_eval.py --report results.json # also write the full result
  python run_eval.py --keep                # leave the S3 prefix for inspection

Recall is per expected (source, rule_id) pair: hit if that pair fired on
that case's file at least once. Extra findings are reported, never counted
against recall -- a case labelled for its encryption pair will also raise a
dozen other S3 rules, and that is correct behaviour, not noise. The
exception is clean-control cases, which expect nothing, so anything they
raise is a false positive and is reported as such.

Also reports **mapping coverage** (spec §7.1's second half): what fraction of
findings have a candidate control in corpus/rule_mappings.json, so
mapping-agent has something to cite rather than leaving them "raw". Read
from the file, not from a mapping-agent run -- it is a property of the
corpus, costs nothing, and is deterministic. It measures whether a finding
*can* be mapped, not whether the agent picks well among the candidates;
that needs a labelled control per case and a run, and is not measured here.
"""

import argparse
import collections
import json
import pathlib
import re
import subprocess
import sys
import time

import boto3

HERE = pathlib.Path(__file__).resolve().parent
CASES = HERE / "cases"

# Must match iac-scanner's SNAPSHOT_SUFFIXES.
SNAPSHOT_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json", ".tofu", ".tofu.json",
                     ".yaml", ".yml", ".bicep")

# ARM templates are .json, which says nothing on its own, so they are admitted
# by content: a top-level $schema naming a deploymentTemplate. An uploader
# applies the cheap text test only and lets the scanner be the authority --
# over-admitting costs one object the scanner re-sniffs and discards, where
# under-admitting loses a file silently. Must match iac-scanner's
# ARM_SCHEMA_RE; corpus/test_corpus.py asserts every copy agrees.
ARM_SCHEMA_RE = re.compile(r'"\$schema"\s*:\s*"[^"]*deploymentTemplate\.json')


def is_snapshot_file(path):
    """Whether the scanner would open this file.

    Suffix for everything that declares itself by name, plus the ARM sniff for
    a bare .json. Note .tf.json and .tofu.json match on suffix first and never
    reach the sniff."""
    if path.name.endswith(SNAPSHOT_SUFFIXES):
        return True
    if not path.name.endswith(".json"):
        return False
    try:
        return bool(ARM_SCHEMA_RE.search(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError):
        return False
RULE_MAPPINGS = HERE.parent / "rule_mappings.json"


def load_mappings():
    """The raw candidate lists, keyed `source:rule_id`."""
    return json.loads(RULE_MAPPINGS.read_text(encoding="utf-8"))["mappings"]


def mapped_pairs(scan_body, mappings):
    """(source, rule_id) pairs with a candidate control that applies to the
    target_type they actually fired with.

    Not simply "the rule has an entry": a candidate may be scoped to one
    target_type (mapping-agent's _candidates_for), so CKV_SECRET_6 on a
    manifest has a Kubernetes control to cite and the same rule on a .tf
    file does not. Counting the entry rather than the applicable candidates
    would report coverage this corpus cannot actually deliver.
    """
    mapped = set()
    for finding in scan_body["findings"]:
        pair = (finding["source"], finding["rule_id"])
        if pair in mapped:
            continue
        target_type = finding.get("target_type")
        refs = mappings.get(f"{pair[0]}:{pair[1]}") or []
        if any("target_type" not in r or r["target_type"] == target_type for r in refs):
            mapped.add(pair)
    return mapped


def bucket_from_terraform():
    out = subprocess.run(
        ["terraform", "output", "-raw", "artifacts_bucket_name"],
        cwd=HERE.parent.parent / "terraform", capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def load_cases():
    cases = {}
    for d in sorted(p for p in CASES.iterdir() if p.is_dir()):
        expected = json.loads((d / "expected.json").read_text(encoding="utf-8"))
        cases[d.name] = {
            # Every scannable file in the case, not just main.tf: a case can
            # be a .tf.json, or a .tf plus the .tfvars that holds the secret,
            # or a .bicep plus the module it deploys.
            #
            # is_snapshot_file rather than a suffix test, because an ARM case's
            # sample is a .json -- and so is every case's own expected.json,
            # which a bare ".json" in SNAPSHOT_SUFFIXES would upload as a
            # sample. The $schema sniff tells them apart.
            "files": {
                p.name: p.read_text(encoding="utf-8")
                for p in sorted(d.iterdir()) if p.name != "expected.json" and is_snapshot_file(p)
            },
            "category": expected["category"],
            "description": expected["description"],
            "expected": {(e["source"], e["rule_id"]) for e in expected["expected"]},
        }
    return cases


def upload(s3, bucket, prefix, cases):
    for name, c in cases.items():
        for filename, content in c["files"].items():
            s3.put_object(Bucket=bucket, Key=f"{prefix}{name}/{filename}", Body=content.encode("utf-8"))


def scan(lam, function, prefix, run_id):
    payload = {"pr_id": run_id, "s3_prefix": prefix, "persist": False}
    resp = lam.invoke(FunctionName=function, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if "FunctionError" in resp:
        sys.exit(f"iac-scanner failed: {body}")
    return body


def delete_prefix(s3, bucket, prefix):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys += [{"Key": o["Key"]} for o in page.get("Contents", [])]
    for i in range(0, len(keys), 1000):
        s3.delete_objects(Bucket=bucket, Delete={"Objects": keys[i:i + 1000]})


def evaluate(cases, scan_body, mapped):
    fired = collections.defaultdict(set)
    for f in scan_body["findings"]:
        case_name = f["file"].split("/", 1)[0]
        fired[case_name].add((f["source"], f["rule_id"]))

    unparsed = {e.split("/", 1)[0] for e in scan_body.get("scan_errors", [])}

    results = {}
    for name, c in cases.items():
        got = fired.get(name, set())
        hits = c["expected"] & got
        results[name] = {
            "category": c["category"],
            "expected": sorted(c["expected"]),
            "hit": sorted(hits),
            "missed": sorted(c["expected"] - got),
            "unexpected": sorted(got - c["expected"]),
            "parse_error": name in unparsed,
            # Of the pairs this case expected AND that fired, how many can be
            # mapped. Scoped to hits because an expected pair the scanner
            # never found is a detection problem, not a mapping one, and
            # counting it twice would blame the corpus for a scanner gap.
            "mapped": sorted(hits & mapped),
            "unmapped": sorted(hits - mapped),
        }
    return results


def summarise(results, scan_body, mapped):
    def recall(rows):
        exp = sum(len(r["expected"]) for r in rows)
        hit = sum(len(r["hit"]) for r in rows)
        return hit, exp

    positives = [r for r in results.values() if r["category"] != "clean-control"]
    controls = [r for r in results.values() if r["category"] == "clean-control"]

    by_cat = collections.defaultdict(list)
    for r in positives:
        by_cat[r["category"]].append(r)
    by_src = collections.defaultdict(lambda: [0, 0])
    for r in positives:
        for src, _ in r["expected"]:
            by_src[src][1] += 1
        for src, _ in r["hit"]:
            by_src[src][0] += 1

    hit, exp = recall(positives)

    # Two mapping numbers, because they answer different questions.
    #
    # Labelled: of the pairs these cases were written to catch and that fired,
    # how many can be mapped. The headline, comparable with recall above.
    #
    # All findings: of everything the scan actually produced, how many can be
    # mapped. Lower and more honest about a real PR, because the labels are a
    # deliberate minimum -- a bare bucket raises a dozen rules and its case
    # expects one pair. This is the number a reviewer's queue would reflect.
    labelled_hits = {p for r in positives for p in map(tuple, r["hit"])}
    all_fired = {(f["source"], f["rule_id"]) for f in scan_body["findings"]}
    unmapped_by_count = collections.Counter(
        f"{src}:{rid}" for f in scan_body["findings"]
        for src, rid in [(f["source"], f["rule_id"])] if (src, rid) not in mapped
    )

    return {
        "overall": {"hit": hit, "expected": exp, "recall": hit / exp if exp else None},
        "mapping": {
            "labelled": {"mapped": len(labelled_hits & mapped), "total": len(labelled_hits)},
            "all_findings": {"mapped": len(all_fired & mapped), "total": len(all_fired)},
            "unmapped_rules": dict(unmapped_by_count.most_common()),
        },
        "by_category": {k: dict(zip(("hit", "expected"), recall(v))) for k, v in sorted(by_cat.items())},
        "by_source": {k: {"hit": v[0], "expected": v[1]} for k, v in sorted(by_src.items())},
        "clean_controls": {r_name: r["unexpected"] for r_name, r in results.items()
                           if r["category"] == "clean-control" and r["unexpected"]},
        "parse_errors": [n for n, r in results.items() if r["parse_error"]],
        "cases": len(results),
        "positives": len(positives),
        "controls": len(controls),
    }


def print_report(results, summary):
    o = summary["overall"]
    print(f"\n{'=' * 70}")
    print(f"DETECTION RECALL  {o['hit']}/{o['expected']}  =  {o['recall']:.1%}"
          f"   ({summary['positives']} positive cases, {summary['controls']} clean controls)")
    print("=" * 70)

    print("\nby category")
    for cat, v in summary["by_category"].items():
        pct = v["hit"] / v["expected"] if v["expected"] else 0
        print(f"  {cat:24s} {v['hit']:3d}/{v['expected']:<3d}  {pct:6.1%}")

    print("\nby source")
    for src, v in summary["by_source"].items():
        pct = v["hit"] / v["expected"] if v["expected"] else 0
        print(f"  {src:24s} {v['hit']:3d}/{v['expected']:<3d}  {pct:6.1%}")

    m = summary["mapping"]
    lab, allf = m["labelled"], m["all_findings"]
    print("\nmapping coverage -- a candidate control exists to cite")
    print(f"  {'labelled pairs that fired':24s} {lab['mapped']:3d}/{lab['total']:<3d}  "
          f"{lab['mapped'] / lab['total'] if lab['total'] else 0:6.1%}")
    print(f"  {'all distinct rules fired':24s} {allf['mapped']:3d}/{allf['total']:<3d}  "
          f"{allf['mapped'] / allf['total'] if allf['total'] else 0:6.1%}")
    if m["unmapped_rules"]:
        print(f"  unmapped, by how often they fired ({len(m['unmapped_rules'])} rules)")
        for rule, n in list(m["unmapped_rules"].items())[:12]:
            print(f"    {n:3d}x  {rule}")
        if len(m["unmapped_rules"]) > 12:
            print(f"    ... and {len(m['unmapped_rules']) - 12} more (full list in --report)")

    misses = [(n, r) for n, r in results.items() if r["missed"]]
    print(f"\nmissed ({sum(len(r['missed']) for _, r in misses)})")
    for name, r in misses:
        for src, rid in r["missed"]:
            print(f"  {name:34s} {src:8s} {rid}")

    if summary["clean_controls"]:
        print("\nclean controls that raised something (false positives)")
        for name, unexpected in summary["clean_controls"].items():
            for src, rid in unexpected:
                print(f"  {name:34s} {src:8s} {rid}")
    else:
        print("\nclean controls: nothing raised")

    if summary["parse_errors"]:
        print(f"\nCASES THAT DID NOT PARSE: {summary['parse_errors']}")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bucket", help="artifacts bucket (default: terraform output)")
    ap.add_argument("--function", default="iacposture-dev-iac-scanner")
    ap.add_argument("--report", type=pathlib.Path, help="write full per-case results as JSON")
    ap.add_argument("--keep", action="store_true", help="leave the S3 prefix in place afterwards")
    args = ap.parse_args()

    bucket = args.bucket or bucket_from_terraform()
    cases = load_cases()
    run_id = f"eval-{time.strftime('%Y%m%dT%H%M%S')}"
    prefix = f"scans/{run_id}/"

    s3 = boto3.client("s3")
    lam = boto3.client("lambda")

    print(f"{len(cases)} cases -> s3://{bucket}/{prefix}")
    upload(s3, bucket, prefix, cases)

    print(f"invoking {args.function} once ...", end="", flush=True)
    t0 = time.time()
    try:
        body = scan(lam, args.function, prefix, run_id)
    finally:
        if not args.keep:
            delete_prefix(s3, bucket, prefix)
    print(f" {time.time() - t0:.0f}s, {body['finding_count']} findings")

    mapped = mapped_pairs(body, load_mappings())
    results = evaluate(cases, body, mapped)
    summary = summarise(results, body, mapped)
    print_report(results, summary)

    if args.report:
        args.report.write_text(json.dumps({
            "run_id": run_id, "function": args.function, "summary": summary,
            "results": results, "raw_finding_count": body["finding_count"],
        }, indent=2), encoding="utf-8")
        print(f"full results -> {args.report}")


if __name__ == "__main__":
    main()
