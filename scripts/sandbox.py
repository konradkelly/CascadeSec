"""Switch the sandbox on and off, and prove it contains what it runs.

    python scripts/sandbox.py up          # apply terraform/sandbox with active=true
    python scripts/sandbox.py down        # apply with active=false: nothing billed while idle
    python scripts/sandbox.py leak-test   # run the containment test; exit 1 unless it passes
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

Needs AWS credentials, terraform on PATH, and boto3 (the repo's .venv).
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import boto3

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


def cmd_status(_args):
    out = outputs()
    print(f"sandbox is {'UP (endpoints billed hourly)' if out.get('active') else 'down (nothing billed while idle)'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "down"):
        p = sub.add_parser(name)
        p.add_argument("--yes", action="store_true", help="apply without asking")
    sub.add_parser("leak-test")
    sub.add_parser("status")
    args = parser.parse_args()

    if args.command == "up":
        apply(True, args.yes)
    elif args.command == "down":
        apply(False, args.yes)
    elif args.command == "leak-test":
        cmd_leak_test(args)
    else:
        cmd_status(args)


if __name__ == "__main__":
    main()
