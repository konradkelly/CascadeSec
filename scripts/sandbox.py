"""Switch the sandbox on and off, and prove it contains what it runs.

    python scripts/sandbox.py up          # apply terraform/sandbox with active=true
    python scripts/sandbox.py down        # apply with active=false: nothing billed while idle
    python scripts/sandbox.py leak-test   # run the containment test; exit 1 unless it passes
    python scripts/sandbox.py synth DIR [--app-dir infra]   # synthesize a local CDK app
    python scripts/sandbox.py status

The sandbox is applied only while in use (docs/sandbox-spec.md §10, decided
2026-10-09). `up` adds the five interface endpoints, about
two minutes; `down` removes them and keeps everything that costs nothing
idle, images and the package mirror's cache included.

The leak test is spec §9 step 1, and nothing else uses the sandbox until it
passes. Two runs:

  1. leak-test, both phases: every way out is tried in the fetch task and in
     the execute task, and graded on the trusted side by
     lambda/sandbox-dispatch/leak.py -- with controls, so a sandbox whose
     network is simply broken fails rather than passes.
  2. sleep, execute only, with a short timeout: the task must not outlive
     its run. Passes when the run ends with States.Timeout and, shortly
     after, no task in its group is still running. Whether Step Functions or
     the reap step stopped it is reported, because spec §7 left that to be
     measured.

`synth` is spec §9 step 2 without GitHub: the directory is packed the way
github-gateway packs a repository (scan.py's SKIP_DIRS, regular files only),
run through cdk-synth, and the outcome printed. On success the templates
and their source maps are in scans/<pr id>/ of the artifacts bucket, where
the pipeline's Scan would read them.

Needs AWS credentials, terraform on PATH, and boto3 (the repo's .venv).
"""

import argparse
import io
import json
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import boto3

from scan import SKIP_DIRS, tf_output, LAMBDA_CONFIG

ROOT = Path(__file__).resolve().parent.parent
TF_DIR = ROOT / "terraform" / "sandbox"

LEAK_TIMEOUT_SECONDS = 300
SLEEP_TIMEOUT_SECONDS = 60
# After the sleep run ends: how long a task may take to reach STOPPED.
STOP_GRACE_SECONDS = 120


def terraform(*args, capture=False):
    cmd = ["terraform", f"-chdir={TF_DIR}", *args]
    if capture:
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    subprocess.run(cmd, check=True)


def outputs():
    raw = json.loads(terraform("output", "-json", capture=True))
    return {k: v["value"] for k, v in raw.items()}


def apply(active, yes):
    args = ["apply", f"-var=active={'true' if active else 'false'}"]
    if yes:
        args.append("-auto-approve")
    terraform(*args)


def start_and_wait(sfn, arn, payload, poll=5):
    started = sfn.start_execution(stateMachineArn=arn, input=json.dumps(payload))
    execution = started["executionArn"]
    print(f"  started {execution.rsplit(':', 1)[-1]}")
    while True:
        desc = sfn.describe_execution(executionArn=execution)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(poll)


def print_checks(leak):
    width = max(len(c["probe"]) for c in leak["checks"])
    for c in leak["checks"]:
        mark = "ok  " if c["passed"] else "FAIL"
        kind = "control" if c["control"] else "leak   "
        print(f"  {mark} {c['phase']:<7} {kind} {c['probe']:<{width}}  "
              f"observed {c['observed']!r:<24} want {c['expect']:<22} {c['meaning']}")
    if leak["unknown_probes"]:
        print(f"  (reported but not graded: {', '.join(leak['unknown_probes'])})")


def leak_run(sfn, arn):
    print("run 1: leak-test, fetch and execute")
    desc = start_and_wait(sfn, arn, {"kind": "leak-test", "phases": ["fetch", "execute"],
                                     "timeout_seconds": LEAK_TIMEOUT_SECONDS})
    if desc["status"] != "SUCCEEDED":
        print(f"  the run itself {desc['status']}: {desc.get('error')} {desc.get('cause', '')[:500]}")
        return False
    out = json.loads(desc["output"])
    for phase, record in out["phases"].items():
        if record.get("error"):
            print(f"  {phase} task error: {record['error']}")
        if record["status"] != "ok":
            print(f"  {phase} result: {record['status']} {record.get('why', '')}")
    print_checks(out["leak"])
    if out["reaped"]:
        print(f"  reaped {len(out['reaped'])} task(s) that outlived their state")
    return out["leak"]["passed"]


def sleep_run(sfn, ecs, arn, cluster):
    print(f"run 2: sleep, execute only, timeout {SLEEP_TIMEOUT_SECONDS}s")
    desc = start_and_wait(sfn, arn, {"kind": "sleep", "phases": ["execute"],
                                     "timeout_seconds": SLEEP_TIMEOUT_SECONDS})
    if desc["status"] != "SUCCEEDED":
        print(f"  the run itself {desc['status']}: {desc.get('error')}")
        return False
    out = json.loads(desc["output"])
    error = (out["phases"]["execute"].get("error") or {}).get("error")
    timed_out = error == "States.Timeout"
    print(f"  {'ok  ' if timed_out else 'FAIL'} execute ended with {error!r}, want 'States.Timeout'")
    stopped_by = "the reap step" if out["reaped"] else "Step Functions"

    group = "sandbox:" + out["run_id"]

    def tasks_in_group(status):
        arns = ecs.list_tasks(cluster=cluster, desiredStatus=status)["taskArns"]
        found = ecs.describe_tasks(cluster=cluster, tasks=arns[:100])["tasks"] if arns else []
        return [t for t in found if t.get("group") == group]

    deadline = time.time() + STOP_GRACE_SECONDS
    while True:
        running = tasks_in_group("RUNNING")
        stopped = tasks_in_group("STOPPED")
        settled = not running and bool(stopped) and all(t["lastStatus"] == "STOPPED" for t in stopped)
        if settled or time.time() > deadline:
            break
        time.sleep(5)
    print(f"  {'ok  ' if settled else 'FAIL'} no task still running after the run "
          f"({len(stopped)} stopped; stopped by {stopped_by})")

    # A timeout proves nothing about stopping a task that never started:
    # one still pulling its image when the clock runs out times out just the
    # same (2026-10-10, when the firewall blocked the pull and this passed).
    started = bool(stopped) and all(t.get("startedAt") and t.get("stopCode") != "TaskFailedToStart"
                                    for t in stopped)
    reasons = "; ".join(sorted({t.get("stoppedReason", "")[:160] for t in stopped}))
    print(f"  {'ok  ' if started else 'FAIL'} the task was running when its run timed out"
          + ("" if started else f" (stopped: {reasons or 'unknown'})"))
    return timed_out and settled and started


def cmd_leak_test(_args):
    out = outputs()
    if not out.get("active"):
        sys.exit("the sandbox is down: run `python scripts/sandbox.py up` first")
    region = out["state_machine_arn"].split(":")[3]
    sfn = boto3.client("stepfunctions", region_name=region)
    ecs = boto3.client("ecs", region_name=region)

    leak_ok = leak_run(sfn, out["state_machine_arn"])
    sleep_ok = sleep_run(sfn, ecs, out["state_machine_arn"], out["cluster_arn"])
    passed = leak_ok and sleep_ok
    print(f"\nleak test {'PASSED' if passed else 'FAILED'}")
    sys.exit(0 if passed else 1)


SYNTH_TIMEOUT_SECONDS = 600


def pack_project(root):
    """The directory as github-gateway's ProjectArchive would hold it."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root)
            if SKIP_DIRS & set(rel.parts) or not path.is_file() or path.is_symlink():
                continue
            info = tarfile.TarInfo(rel.as_posix())
            info.size, info.mode, info.mtime = path.stat().st_size, 0o644, 0
            with path.open("rb") as fh:
                tar.addfile(info, fh)
    return buf.getvalue()


def cmd_synth(args):
    out = outputs()
    if not out.get("active"):
        sys.exit("the sandbox is down: run `python scripts/sandbox.py up` first")
    root = Path(args.dir).resolve()
    app_dir = args.app_dir.strip("/") or "."
    if not (root / app_dir / "cdk.json").is_file():
        sys.exit(f"no cdk.json in {root / app_dir}")
    region = out["state_machine_arn"].split(":")[3]
    s3 = boto3.client("s3", region_name=region)
    sfn = boto3.client("stepfunctions", region_name=region)

    pr_id = f"manual-synth-{int(time.time())}"
    project_key = f"projects/{pr_id}/local.tgz"
    body = pack_project(root)
    s3.put_object(Bucket=out["artifacts_bucket"], Key=project_key, Body=body)
    print(f"packed {root} ({len(body) // 1024} KB) as {pr_id}, app {app_dir}")

    desc = start_and_wait(sfn, out["state_machine_arn"], {
        "kind": "cdk-synth", "phases": ["fetch", "execute"], "timeout_seconds": SYNTH_TIMEOUT_SECONDS,
        "pr_id": pr_id, "app_dir": app_dir, "project_key": project_key})
    if desc["status"] != "SUCCEEDED":
        print(f"  the run itself {desc['status']}: {desc.get('error')} {desc.get('cause', '')[:500]}")
        sys.exit(1)
    result = json.loads(desc["output"])
    for phase, record in result["phases"].items():
        r = record.get("result") or {}
        took = f" in {r['duration_ms'] / 1000:.0f}s" if r.get("duration_ms") else ""
        print(f"  {phase:<7} {record['status']} {r.get('status', '')}{took}"
              f"{' -- ' + r['reason'] if r.get('reason') else ''}")
        if record.get("error"):
            print(f"          task error: {record['error']}")
        if args.log and r.get("log_tail"):
            print("          " + r["log_tail"][-1500:].replace("\n", "\n          "))
    synth = result["synth"]
    print(f"synth {synth['status']}" + (f": {synth['reason']}" if synth.get("reason") else ""))
    for stack in synth.get("stacks") or []:
        print(f"  {stack['stack']}: {stack['resources']} resource(s), {stack['unlocated']} without a source line"
              f" -> s3://{out['artifacts_bucket']}/scans/{pr_id}/{stack['template']}")
    sys.exit(0 if synth["status"] == "ok" else 1)


def cmd_status(_args):
    out = outputs()
    print(f"sandbox is {'UP (endpoints billed hourly)' if out.get('active') else 'down (nothing billed while idle)'}")


def cmd_pulumi(args):
    root = Path(args.dir).resolve()
    app_dir = args.app_dir
    if app_dir != "." and (Path(app_dir).is_absolute() or "\\" in app_dir
                           or any(p in {"", ".", ".."} for p in app_dir.split("/"))):
        sys.exit("--app-dir must be a repository-relative path")
    if not (root / app_dir / "Pulumi.yaml").is_file():
        sys.exit(f"no Pulumi.yaml in {root / app_dir}")
    config = json.loads(Path(args.config).read_text(encoding="utf-8")) if args.config else {}
    calls = json.loads(Path(args.mock_calls).read_text(encoding="utf-8")) if args.mock_calls else {}
    out = outputs()
    if not out.get("active"):
        sys.exit("the sandbox is down: run `python scripts/sandbox.py up` first")
    region = out["state_machine_arn"].split(":")[3]
    s3 = boto3.client("s3", region_name=region)
    sfn = boto3.client("stepfunctions", region_name=region)
    pr_id = f"manual-pulumi-{int(time.time())}"
    project_key = f"projects/{pr_id}/local.tgz"
    s3.put_object(Bucket=out["artifacts_bucket"], Key=project_key, Body=pack_project(root))
    desc = start_and_wait(sfn, out["state_machine_arn"], {
        "kind": "pulumi-mock", "phases": ["fetch", "execute"], "timeout_seconds": SYNTH_TIMEOUT_SECONDS,
        "pr_id": pr_id, "app_dir": app_dir, "project_key": project_key,
        "config": config, "mock_calls": calls})
    if desc["status"] != "SUCCEEDED":
        sys.exit(f"sandbox execution {desc['status']}: {desc.get('error')}")
    result = json.loads(desc["output"])
    for phase, record in result["phases"].items():
        detail = record.get("result") or {}
        print(f"  {phase}: {record['status']} {detail.get('status', '')} {detail.get('reason') or ''}")
        if args.log and detail.get("log_tail"):
            print(detail["log_tail"])
    pulumi = result["pulumi"]
    print(f"Pulumi mocks: {pulumi['status']} {pulumi.get('reason') or ''}")
    if pulumi["status"] != "ok":
        sys.exit(1)
    response = s3.get_object(Bucket=out["sandbox_bucket"], Key=pulumi["resources_key"])
    try:
        data = response["Body"].read()
    finally:
        response["Body"].close()
    target = Path(args.output).resolve()
    target.write_bytes(data)
    print(f"Captured {pulumi['resources']} resource(s) in {target}")
    plan_path = target.with_suffix(".pulumi.plan.json")
    response = s3.get_object(Bucket=out["artifacts_bucket"], Key=pulumi["plan_key"])
    try:
        plan_path.write_bytes(response["Body"].read())
    finally:
        response["Body"].close()
    print(f"Scanner plan: {plan_path}")
    if args.scan:
        client = boto3.client("lambda", region_name=region, config=LAMBDA_CONFIG)
        scan = client.invoke(FunctionName=tf_output("iac_scanner_function_name"),
            Payload=json.dumps({"pr_id": pr_id, "s3_prefix": pulumi["scan_prefix"], "persist": False}).encode())
        result = json.loads(scan["Payload"].read())
        if scan.get("FunctionError"):
            sys.exit(f"scanner failed: {result}")
        findings_path = target.with_suffix(".findings.json")
        findings_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Scan: {result['finding_count']} finding(s), {len(result['scan_errors'])} parse error(s) -> {findings_path}")
        if result["scan_errors"]:
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "down"):
        p = sub.add_parser(name)
        p.add_argument("--yes", action="store_true", help="apply without asking")
    sub.add_parser("leak-test")
    synth = sub.add_parser("synth", help="synthesize a local CDK app in the sandbox")
    synth.add_argument("dir", help="the repository (or project) root to pack")
    synth.add_argument("--app-dir", default=".", help="the app's directory within it (holds cdk.json)")
    synth.add_argument("--log", action="store_true", help="print each phase's log tail")
    pulumi = sub.add_parser("pulumi", help="execute a Node.js Pulumi project under mocks in the sandbox")
    pulumi.add_argument("dir", help="the repository root to pack")
    pulumi.add_argument("--app-dir", default=".", help="directory containing Pulumi.yaml")
    pulumi.add_argument("--config", help="JSON object of fully qualified config keys and string values")
    pulumi.add_argument("--mock-calls", help="JSON object of lookup tokens and explicit input/output fixtures")
    pulumi.add_argument("--output", default="pulumi-resources.json", help="local destination for captured resources")
    pulumi.add_argument("--log", action="store_true", help="print each phase's log tail")
    pulumi.add_argument("--scan", action="store_true", help="scan the generated plan without persisting findings or drafting fixes")
    sub.add_parser("status")
    args = parser.parse_args()

    if args.command == "up":
        apply(True, args.yes)
    elif args.command == "down":
        apply(False, args.yes)
    elif args.command == "leak-test":
        cmd_leak_test(args)
    elif args.command == "synth":
        cmd_synth(args)
    elif args.command == "pulumi":
        cmd_pulumi(args)
    else:
        cmd_status(args)


if __name__ == "__main__":
    main()
