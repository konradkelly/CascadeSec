#!/usr/bin/env python3
"""Run the v1 pipeline against a directory of Terraform, end to end.

Spec §8 v1 calls for a "manual trigger (CLI or simple upload)". This is the
one command: it uploads the directory and starts one execution of the
pipeline state machine (terraform/step_functions.tf), which runs the stages
and fans remediation out one file at a time.

  python scripts/scan.py path/to/terraform
  python scripts/scan.py path/to/terraform --pr-id my-run-1
  python scripts/scan.py path/to/terraform --no-remediate           # stop after map
  python scripts/scan.py path/to/terraform --yes                    # skip the cost prompt
  python scripts/scan.py path/to/terraform --pr-id my-run-1 --stages remediate

Stages, each printed as the execution reaches it:

  upload     every .tf, .tf.json, .tfvars, .tfvars.json, .tofu, .tofu.json,
             .yaml and .yml under the directory -> s3://<bucket>/scans/<pr_id>/  (.tfvars is
             where hardcoded secrets live and variables resolve; the YAML is
             for context-agent -- the scanner ignores it)
  scan       iac-scanner, persist=true -> raw findings in DynamoDB
  map        mapping-agent -> control citations, status "mapped"
  remediate  remediation-agent, once per file in parallel -> one model call
             per mapped finding (two, plus a context-agent lookup, when the
             draft asks the repository a question), plus a self-check scan
             per fix. This is the stage that costs money and minutes, so it
             asks first unless --yes or --no-remediate.

--stages bypasses the state machine and invokes the Lambdas directly, one
synchronous call per stage, the way this script worked before the pipeline
existed. It is kept for the case where only one stage should run: redrafting
the findings a reviewer's edit reopened (docs/reviewer-edit-spec.md) is
`--stages remediate` against the existing PR, with no re-upload and no
re-scan. That path is whole-PR and serial; if remediation-agent yields with
findings left, it says so and the command is re-run. (Until the scanner
learned to preserve review state -- spec §8.4 item 3 -- this was not a
convenience but the only safe way to redraft, because scanning again reset
every finding on the PR.)

Re-running with the same --pr-id is safe: a finding that fires again keeps
its status, control mapping, proposed fix and review trail, and one that has
stopped firing is marked rather than removed. Only the scanner's own fields
are refreshed. A new id gives a clean slate. Needs AWS credentials for the dev account and `terraform`
on PATH (only to read names from `terraform output`; pass them explicitly to
skip it).
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

import boto3
from botocore.config import Config

REPO = pathlib.Path(__file__).resolve().parents[1]

# iac-scanner's SNAPSHOT_SUFFIXES plus the manifests context-agent may
# read (its CONTEXT_SUFFIXES). Each function downloads only what it
# recognises, so a .yaml here never reaches the scanner and anything outside
# both sets is never uploaded.
SNAPSHOT_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json",
                     ".tofu", ".tofu.json", ".yaml", ".yml")

# remediation-agent may run for its full 900s. The read timeout has to
# outlast it, and retries have to be OFF: a retried RequestResponse invoke of
# a Lambda that is still running would start a second copy of the same
# remediation, doubling the model calls and racing the first on every write.
LAMBDA_CONFIG = Config(read_timeout=920, connect_timeout=10, retries={"max_attempts": 0})

POLL_SECONDS = 5


def tf_output(name):
    out = subprocess.run(
        ["terraform", "output", "-raw", name],
        cwd=REPO / "terraform", capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


# Directories that are never the repository's own configuration. A real repo
# carries hundreds of YAML files under node_modules alone, and every one
# would be listed to context-agent as somewhere it might look.
SKIP_DIRS = {".terraform", ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def collect_tf_files(root):
    files = sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.name.endswith(SNAPSHOT_SUFFIXES) and not (SKIP_DIRS & set(p.parts))
    )
    if not files:
        sys.exit(f"no Terraform files under {root}")
    return files


def upload(s3, bucket, pr_id, root, files):
    """Make the snapshot match the directory, and say what it removed.

    Uploading without removing made the snapshot additive: a file deleted
    locally stayed in S3 and kept being scanned, so its findings could never
    stop firing and the scanner's no_longer_detected mark was unreachable by
    the one route a user would try. Only scans/<pr_id>/ is touched -- a fix's
    content lives under fixes/ and is the base later fixes are drafted on.
    """
    prefix = f"scans/{pr_id}/"
    wanted = {prefix + path.relative_to(root).as_posix(): path for path in files}
    existing = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        existing.update(o["Key"] for o in page.get("Contents", []))

    for key, path in wanted.items():
        s3.put_object(Bucket=bucket, Key=key, Body=path.read_bytes())
    removed = sorted(existing - set(wanted))
    for chunk in (removed[i:i + 1000] for i in range(0, len(removed), 1000)):
        s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": k} for k in chunk]})
    return prefix, removed


def confirm(prompt):
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def print_scan(body):
    print(f"           {body['finding_count']} finding(s)", end="")
    # Only on a re-scan: how many were already on this PR and kept their
    # review state, and how many the scan no longer reports.
    if body.get("preserved_count"):
        print(f", {body['preserved_count']} already reviewed or mapped (kept)", end="")
    if body.get("no_longer_detected_count"):
        print(f", {body['no_longer_detected_count']} no longer detected", end="")
    if body.get("scan_errors"):
        print(f", could not parse: {body['scan_errors']}", end="")
    print()


def print_map(body):
    print(f"           {body['mapped_count']} mapped, {body['skipped_count']} with no candidate control")


def print_remediation(body, label="          "):
    print(f"{label} {body['fix_proposed_count']} fix-proposed, "
          f"{body['needs_human_only_count']} needs-human-only, "
          f"{body['superseded_count']} superseded, "
          f"{body['error_count']} error(s)", end="")
    if body.get("remaining"):
        print(f", {body['remaining']} not reached", end="")
    print()


# ---------- the pipeline ----------

def execution_name(pr_id):
    # Names must be unique per state machine for 90 days and drawn from a
    # restricted alphabet; pr_id is neither, since a re-run reuses it.
    raw = f"{pr_id}-{time.strftime('%Y%m%dT%H%M%S')}"
    return re.sub(r"[^A-Za-z0-9_-]", "-", raw)[:80]


def run_pipeline(sfn, state_machine_arn, pr_id, prefix, remediate):
    """Start one execution and narrate it from its event history.

    Polled rather than streamed -- Step Functions has no push API for
    history -- and printed per state so the terminal reads the same as the
    direct-invoke path did: a line when a stage finishes, not a spinner.
    """
    execution_arn = sfn.start_execution(
        stateMachineArn=state_machine_arn,
        name=execution_name(pr_id),
        input=json.dumps({
            "pr_id": pr_id, "s3_prefix": prefix,
            "remediate": remediate,
        }),
    )["executionArn"]
    print(f"execution  {execution_arn.rsplit(':', 1)[-1]}")

    seen = 0
    started = {}
    while True:
        for event in execution_events(sfn, execution_arn)[seen:]:
            seen += 1
            narrate(event, started)
        status = sfn.describe_execution(executionArn=execution_arn)["status"]
        if status != "RUNNING":
            break
        time.sleep(POLL_SECONDS)

    if status != "SUCCEEDED":
        sys.exit(f"execution {status}: see {execution_arn}")
    output = json.loads(sfn.describe_execution(executionArn=execution_arn)["output"])
    per_file = output.get("remediation") or []
    if per_file:
        totals = {k: sum(f[k] for f in per_file) for k in (
            "fix_proposed_count", "needs_human_only_count", "superseded_count", "error_count",
        )}
        print_remediation(totals, label="           total:")
    return output


def execution_events(sfn, execution_arn):
    events = []
    kwargs = {"executionArn": execution_arn, "maxResults": 1000}
    while True:
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        if "nextToken" not in page:
            return events
        kwargs["nextToken"] = page["nextToken"]


# State name -> where the state machine puts its output (also the label the
# line is printed under), and the printer for it.
STAGES = {
    "Scan":          ("scan", print_scan),
    "MapToControls": ("map", print_map),
}


def narrate(event, started):
    """Print one line per finished state. `started` remembers when each was
    entered, keyed by state name plus file -- the Map runs several
    RemediateFile states at once, and they all share the one name."""
    kind = event["type"]
    if kind == "TaskStateEntered":
        details = event["stateEnteredEventDetails"]
        name = details["name"]
        payload = json.loads(details.get("input") or "{}")
        started[(name, payload.get("file"))] = event["timestamp"]
        if name in STAGES:
            print(f"{STAGES[name][0]:10s} ...", end="", flush=True)
        return
    if kind != "TaskStateExited":
        return
    details = event["stateExitedEventDetails"]
    name = details["name"]
    output = json.loads(details.get("output") or "{}")
    entered = started.pop((name, output.get("file")), event["timestamp"])
    elapsed = (event["timestamp"] - entered).total_seconds()
    if name in STAGES:
        key, show = STAGES[name]
        print(f" {elapsed:.0f}s")
        show(output.get(key, {}))
    elif name == "RemediateFile":
        if output.get("remaining"):
            print(f"remediate  {output['file']}: {elapsed:.0f}s, continuing "
                  f"({output['remaining']} left)")
        else:
            print(f"remediate  {output['file']}: {elapsed:.0f}s")
            print_remediation(output)


# ---------- direct invokes (--stages) ----------

def invoke(lam, function, payload, label):
    print(f"{label:10s} {function} ...", end="", flush=True)
    t0 = time.time()
    resp = lam.invoke(
        FunctionName=function, InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    elapsed = time.time() - t0
    if "FunctionError" in resp:
        print(f" FAILED after {elapsed:.0f}s")
        sys.exit(f"{function}: {body.get('errorType')}: {body.get('errorMessage')}")
    print(f" {elapsed:.0f}s")
    return body


def run_stages(args, stages, pr_id, prefix):
    scanner = args.scanner or tf_output("iac_scanner_function_name")
    mapper = args.mapper or tf_output("mapping_agent_function_name")
    remediator = args.remediator or tf_output("remediation_agent_function_name")
    lam = boto3.client("lambda", config=LAMBDA_CONFIG)

    body = None
    if "scan" in stages:
        body = invoke(lam, scanner, {
            "pr_id": pr_id, "s3_prefix": prefix, "persist": True,
        }, "scan")
        print_scan(body)

    if "map" in stages:
        # Same loop the state machine runs: mapping-agent yields before its
        # timeout with `remaining` > 0, and the counts it carries go back in.
        body = invoke(lam, mapper, {"pr_id": pr_id}, "map")
        while body.get("remaining"):
            body = invoke(lam, mapper, {
                "pr_id": pr_id, "mapped_count": body["mapped_count"], "files": body["files"],
            }, "map")
        print_map(body)

    if "remediate" in stages:
        what = (f"{body['mapped_count']} mapped finding(s)" if "map" in stages
                else "every mapped finding on this PR")
        if not args.yes and not confirm(
            f"           remediate {what}? One model call and one self-check scan each."
        ):
            print("           skipped")
        else:
            body = invoke(lam, remediator, {"pr_id": pr_id}, "remediate")
            print_remediation(body)
            if body.get("remaining"):
                print("           re-run with --stages remediate to continue")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("directory", type=pathlib.Path, help="Terraform root to scan (recursively)")
    ap.add_argument("--pr-id", help="default: manual-<dirname>-<timestamp>")
    ap.add_argument("--no-remediate", action="store_true", help="stop the pipeline after mapping")
    ap.add_argument("--yes", action="store_true", help="don't ask before the remediation stage")
    ap.add_argument("--stages",
                    help="comma-separated subset of scan,map,remediate, invoked directly rather "
                         "than through the pipeline (see above for when that is wanted)")
    ap.add_argument("--bucket", help="artifacts bucket (default: terraform output)")
    ap.add_argument("--pipeline", help="pipeline state machine ARN (default: terraform output)")
    ap.add_argument("--scanner", help="iac-scanner function name (default: terraform output)")
    ap.add_argument("--mapper", help="mapping-agent function name (default: terraform output)")
    ap.add_argument("--remediator", help="remediation-agent function name (default: terraform output)")
    args = ap.parse_args()

    root = args.directory.resolve()
    if not root.is_dir():
        sys.exit(f"not a directory: {root}")
    stages = None
    if args.stages:
        stages = [s.strip() for s in args.stages.split(",") if s.strip()]
        unknown = set(stages) - {"scan", "map", "remediate"}
        if unknown:
            sys.exit(f"unknown stage(s): {sorted(unknown)}")

    pr_id = args.pr_id or f"manual-{root.name}-{time.strftime('%Y%m%dT%H%M%S')}"
    bucket = args.bucket or tf_output("artifacts_bucket_name")

    s3 = boto3.client("s3")
    files = collect_tf_files(root)
    print(f"pr_id      {pr_id}")
    prefix, removed = upload(s3, bucket, pr_id, root, files)
    print(f"upload     {len(files)} file(s) -> s3://{bucket}/{prefix}", end="")
    if removed:
        # Their findings will stop firing, and the scan line below says so.
        print(f", {len(removed)} no longer in the directory (removed)", end="")
    print()

    if stages:
        run_stages(args, stages, pr_id, prefix)
    else:
        # Asked up front: once the execution starts there is no one to ask.
        remediate = not args.no_remediate and (args.yes or confirm(
            "           remediate every mapped finding? One model call and one self-check scan each."
        ))
        if not remediate and not args.no_remediate:
            print("           remediation will be skipped")
        state_machine_arn = args.pipeline or tf_output("pipeline_state_machine_arn")
        run_pipeline(boto3.client("stepfunctions"), state_machine_arn, pr_id, prefix, remediate)

    try:
        url = tf_output("dashboard_url")
        print(f"\nreview     {url}/prs/{pr_id}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass


if __name__ == "__main__":
    main()
