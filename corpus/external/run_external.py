#!/usr/bin/env python3
"""Scan third-party Terraform repositories with the deployed iac-scanner.

The labelled corpus next door (../eval) measures recall: did the pairs each
case was written to catch fire. It cannot measure what it was not written
for, and every case in it was written by someone who already knew what the
scanner looks for. This harness points the same deployed function at
repositories nobody here wrote, and reports the things a label cannot:

  - parse robustness: scan_errors on real module trees, for_each/dynamic
    blocks, provider aliases, per-environment .tfvars
  - scale: wall time and whether the invocation finished at all
  - mapping coverage on the real long tail of rules, not the corpus's
  - false-positive load on repositories that are meant to be clean

No recall number comes out of this, because there are no labels. What
comes out is a baseline per repository -- file count, finding count,
distinct rules, scan errors -- that a later run is compared against. The
repository is pinned to a commit and the tools are pinned in the image, so
the scan is deterministic and any drift means the scanner changed.

Usage:
  python run_external.py                    # every repo in repos.json
  python run_external.py terragoat vpc      # by name, or a unique substring
  python run_external.py --pin              # write the sha each unpinned repo resolved to
  python run_external.py --baseline         # write this run's counts as each repo's baseline
  python run_external.py --report out.json  # keep every finding, per repo
  python run_external.py --keep             # leave the S3 prefixes for inspection

Needs git, boto3, AWS credentials for the dev account, and the terraform CLI
on PATH (only to read the bucket name; --bucket skips it). Repositories are
cloned into .repos/ next to this file, shallow and at the pinned commit;
nothing from them is committed here. One scanner invocation per repository,
so a timeout on one does not take the others with it.
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
from botocore.config import Config
from botocore.exceptions import ClientError, ReadTimeoutError

HERE = pathlib.Path(__file__).resolve().parent
MANIFEST = HERE / "repos.json"
CLONES = HERE / ".repos"

# The eval harness already knows the bucket, the mappings file, and how to
# clear a prefix; there is no reason to have two of each.
sys.path.insert(0, str(HERE.parent / "eval"))
from run_eval import (  # noqa: E402
    bucket_from_terraform, delete_prefix, load_mappings, mapped_pairs,
)

# Must match iac-scanner's SNAPSHOT_SUFFIXES and scripts/scan.py's SKIP_DIRS:
# what scan.py would upload is what a real run would scan.
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
SKIP_DIRS = {".terraform", ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

# The scanner's own timeout is 300s (terraform/lambda_iac_scanner.tf). boto3's
# default read timeout is 60s, which would abandon a legitimately slow scan
# of a large repository and then retry it -- so no retries, and a read
# timeout past the function's.
LAMBDA_CONFIG = Config(read_timeout=330, connect_timeout=10, retries={"max_attempts": 0})

BASELINE_KEYS = ("files", "findings", "distinct_ids", "distinct_rules", "scan_errors")


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def checkout(repo):
    """Put the repository at its pinned commit under .repos/<name>; return the sha.

    Shallow either way. A pinned sha is fetched directly -- GitHub serves any
    reachable commit by sha -- so the clone is one commit deep regardless of
    how far behind the pin has fallen. Unpinned, the default branch's tip is
    what gets scanned and reported, and --pin writes it back.
    """
    dest = CLONES / repo["name"]
    sha = repo.get("sha")
    if dest.exists():
        have = git("rev-parse", "HEAD", cwd=dest)
        if sha is None or have == sha:
            return have
        git("fetch", "--depth", "1", "origin", sha, cwd=dest)
        git("checkout", "--quiet", "FETCH_HEAD", cwd=dest)
        return sha
    dest.parent.mkdir(exist_ok=True)
    if sha is None:
        git("clone", "--quiet", "--depth", "1", repo["url"], str(dest))
        return git("rev-parse", "HEAD", cwd=dest)
    dest.mkdir()
    git("init", "--quiet", cwd=dest)
    git("remote", "add", "origin", repo["url"], cwd=dest)
    git("fetch", "--quiet", "--depth", "1", "origin", sha, cwd=dest)
    git("checkout", "--quiet", "FETCH_HEAD", cwd=dest)
    return sha


def collect(root):
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and not (SKIP_DIRS & set(p.parts)) and is_snapshot_file(p)
    )


def upload(s3, bucket, prefix, root, files):
    for path in files:
        s3.put_object(Bucket=bucket, Key=prefix + path.relative_to(root).as_posix(), Body=path.read_bytes())


def scan(lam, function, prefix, run_id):
    """The scanner's response body, or {"error": ...} for anything short of one.

    A timeout or an unhandled exception in the function is a result of this
    harness, not a reason to stop it: "terraform-aws-eks did not finish in
    300s" is exactly the kind of thing it exists to find out.
    """
    payload = {"pr_id": run_id, "s3_prefix": prefix, "persist": False}
    try:
        resp = lam.invoke(FunctionName=function, InvocationType="RequestResponse",
                          Payload=json.dumps(payload).encode("utf-8"))
    except ReadTimeoutError:
        return {"error": f"no response within {LAMBDA_CONFIG.read_timeout}s (function timeout is 300s)"}
    except ClientError as exc:
        return {"error": str(exc)}
    body = json.loads(resp["Payload"].read())
    if "FunctionError" in resp:
        return {"error": f"{body.get('errorType')}: {body.get('errorMessage')}"}
    return body


def summarise(body, mapped):
    findings = body["findings"]
    distinct = {(f["source"], f["rule_id"]) for f in findings}
    unmapped = collections.Counter(
        f"{f['source']}:{f['rule_id']}" for f in findings if (f["source"], f["rule_id"]) not in mapped
    )
    return {
        "findings": len(findings),
        # What a reviewer's queue holds. The tools report a module's resource
        # once per instantiation, so a root module with thirteen examples
        # raises the same finding_id thirteen times; _write_findings keeps
        # one, and mapping-agent reads the table, not this count.
        "distinct_ids": len({f["finding_id"] for f in findings}),
        "distinct_rules": len(distinct),
        "scan_errors": len(body["scan_errors"]),
        "scan_error_files": body["scan_errors"],
        "by_source": dict(collections.Counter(f["source"] for f in findings)),
        "by_severity": dict(collections.Counter(f["severity"] for f in findings).most_common()),
        "top_rules": dict(collections.Counter(f"{f['source']}:{f['rule_id']}" for f in findings).most_common(10)),
        "files_with_findings": len({f["file"] for f in findings}),
        "mapping": {"mapped": len(distinct & mapped), "total": len(distinct)},
        "unmapped_rules": dict(unmapped.most_common()),
    }


def drift(baseline, observed):
    return {k: (baseline[k], observed[k]) for k in BASELINE_KEYS if k in baseline and baseline[k] != observed[k]}


def fmt_counts(counts):
    return " ".join(f"{k}={v}" for k, v in counts.items())


def print_repo(name, result, mapped_names):
    print(f"\n{'=' * 70}\n{name}  @ {result['sha'][:12]}\n{'=' * 70}")
    if "error" in result:
        print(f"  FAILED: {result['error']}")
        return
    s = result["summary"]
    print(f"  {result['files']} files uploaded, {result['elapsed']:.0f}s")
    print(f"  {s['findings']} findings ({s['distinct_ids']} distinct ids) over {s['files_with_findings']} files, "
          f"{s['distinct_rules']} distinct rules   {fmt_counts(s['by_source'])}")
    print(f"  severity: {fmt_counts(s['by_severity'])}")
    if s["scan_errors"]:
        print(f"  SCAN ERRORS ({s['scan_errors']}):")
        for f in s["scan_error_files"]:
            print(f"    {f}")
    m = s["mapping"]
    print(f"  mapping coverage: {m['mapped']}/{m['total']} distinct rules"
          f"  {m['mapped'] / m['total'] if m['total'] else 0:.0%}")
    print("  most frequent rules:")
    for rule, n in s["top_rules"].items():
        print(f"    {n:4d}x {' ' if rule in mapped_names else '*'} {rule}")
    if any(r not in mapped_names for r in s["top_rules"]):
        print("    * no candidate control in rule_mappings.json")
    if result["drift"]:
        print("  DRIFT from baseline:")
        for k, (was, now) in result["drift"].items():
            print(f"    {k}: {was} -> {now}")
    elif result["baseline"]:
        print("  matches baseline")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="repos to run (name or unique substring); default all")
    ap.add_argument("--bucket", help="artifacts bucket (default: terraform output)")
    ap.add_argument("--function", default="iacposture-dev-iac-scanner")
    ap.add_argument("--pin", action="store_true", help="write resolved shas for unpinned repos into repos.json")
    ap.add_argument("--baseline", action="store_true", help="write this run's counts into repos.json as the baseline")
    ap.add_argument("--report", type=pathlib.Path, help="write every finding, per repo, as JSON")
    ap.add_argument("--keep", action="store_true", help="leave the S3 prefixes in place afterwards")
    args = ap.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    repos = manifest["repos"]
    if args.names:
        chosen = []
        for want in args.names:
            hits = [r for r in repos if want in r["name"]]
            if len(hits) != 1:
                sys.exit(f"{want!r} matches {len(hits)} repos: {[r['name'] for r in hits]}")
            chosen += hits
        repos = chosen

    bucket = args.bucket or bucket_from_terraform()
    # Which candidates apply depends on the target_type a rule fired with, so
    # coverage is computed per repository from its own findings rather than
    # once from the file (corpus/README.md, scoped candidates).
    mappings = load_mappings()
    s3 = boto3.client("s3")
    lam = boto3.client("lambda", config=LAMBDA_CONFIG)
    stamp = time.strftime("%Y%m%dT%H%M%S")

    report = {}
    for repo in repos:
        name = repo["name"]
        print(f"{name}: checkout ...", end="", flush=True)
        sha = checkout(repo)
        if args.pin and repo.get("sha") is None:
            repo["sha"] = sha
        root = CLONES / name / repo["subdir"] if repo.get("subdir") else CLONES / name
        files = collect(root)
        print(f" {sha[:12]}, {len(files)} snapshot files", end="", flush=True)

        result = {"sha": sha, "files": len(files), "baseline": repo.get("baseline"), "drift": {}}
        if not files:
            # The scanner would raise on an empty snapshot; "no Terraform
            # files" is the finding here, and it costs nothing to know it
            # before an upload.
            result["error"] = "no files match SNAPSHOT_SUFFIXES; the scanner would raise on an empty snapshot"
            print()
        else:
            run_id = f"external-{name}-{stamp}"
            prefix = f"scans/{run_id}/"
            print(", uploading ...", end="", flush=True)
            upload(s3, bucket, prefix, root, files)
            print(" scanning ...", end="", flush=True)
            t0 = time.time()
            try:
                body = scan(lam, args.function, prefix, run_id)
            finally:
                if not args.keep:
                    delete_prefix(s3, bucket, prefix)
            result["elapsed"] = time.time() - t0
            print(f" {result['elapsed']:.0f}s")
            if "error" in body:
                result["error"] = body["error"]
            else:
                mapped = mapped_pairs(body, mappings)
                result["mapped_names"] = sorted(f"{src}:{rid}" for src, rid in mapped)
                result["summary"] = summarise(body, mapped)
                result["findings"] = body["findings"]
                observed = {"files": len(files), **{k: result["summary"][k] for k in BASELINE_KEYS[1:]}}
                result["drift"] = drift(repo.get("baseline") or {}, observed)
                if args.baseline:
                    repo["baseline"] = observed
        report[name] = result

    for name, result in report.items():
        print_repo(name, result, set(result.get("mapped_names") or ()))
    print()

    if args.pin or args.baseline:
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"updated {MANIFEST.name}")
    if args.report:
        args.report.write_text(json.dumps({
            "run": stamp, "function": args.function, "repos": report,
        }, indent=2), encoding="utf-8")
        print(f"full results -> {args.report}")

    failed = [n for n, r in report.items() if "error" in r]
    drifted = [n for n, r in report.items() if r["drift"]]
    if failed or drifted:
        sys.exit(f"failed: {failed}  drifted: {drifted}")


if __name__ == "__main__":
    main()
