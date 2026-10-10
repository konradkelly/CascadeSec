"""sandbox-dispatch Lambda (docs/sandbox-spec.md §6, §7).

The trusted side of a sandbox run. Invoked by the sandbox-run state machine
with an "action":

  prepare  validate the request, mint a run id, and write each phase a
           manifest: its presigned URLs and, for fetch, a CodeArtifact token.
           The task is handed only the manifest's own URL. Returns the
           execution's initial state.
  reap     stop any task in this run's group that is still meant to be
           running: a timed-out state is not proof that its task stopped
           (spec §7).
  collect  read each phase's result.json as hostile input -- capped, parsed,
           shape-checked -- and, for a leak test, grade it (leak.py). For
           cdk-synth, read the assembly the same way and write each stack's
           rewritten template and source map into the pull request's scan
           prefix (cdk.py).

What the task receives is decided here, never by the request: the request
names a kind and phases, and the kind selects a harness in the image. A
pull request supplies files, never a command line.

Two credentials leave this function, both deliberately narrow:
  - presigned URLs, each good for one object, signed with this role's
    session -- the URL carries the session token but not the secret, so it
    cannot be used to sign anything else;
  - a CodeArtifact bearer token for the fetch task, fifteen minutes, with
    this role's CodeArtifact rights, which are read-only on the mirrors.

Both go in the manifest, not in the task's environment. The environment is
a container override, and ECS caps overrides at 8192 characters: three
URLs and a token measured 7363 on the first deployed run, with step 2's
snapshot and dependency URLs still to come. It also kept every credential
in plain view in the execution's history and the task's description. The
manifest's own URL is the one thing left there, and it expires with them.
"""

import json
import logging
import os
import re
import socket
import urllib.parse
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import cdk
import leak

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
SANDBOX_BUCKET = os.environ.get("SANDBOX_BUCKET", "")
CANARY_BUCKET = os.environ.get("CANARY_BUCKET", "")
CLUSTER_ARN = os.environ.get("CLUSTER_ARN", "")
CODEARTIFACT_DOMAIN = os.environ.get("CODEARTIFACT_DOMAIN", "")
CODEARTIFACT_OWNER = os.environ.get("CODEARTIFACT_OWNER", "")
CODEARTIFACT_NPM_REPO = os.environ.get("CODEARTIFACT_NPM_REPO", "")
ECR_REGISTRY = os.environ.get("ECR_REGISTRY", "")
# The main stack's bucket: where a project tarball comes from, and where a
# synthesized template goes to be scanned (spec §7, Detection).
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET", "")
# Whether the interface endpoints exist (terraform/sandbox's `active`).
# Without them no task can start, so a run is answered "unavailable" at
# once rather than after a task has failed to pull its image.
SANDBOX_ACTIVE = os.environ.get("SANDBOX_ACTIVE", "true") == "true"

# pulumi-mock and test-suite arrive with the harnesses that run them
# (spec §9).
KINDS = {"leak-test", "sleep", "cdk-synth"}
PHASES = ("fetch", "execute")

MIN_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 1800
# A URL must outlive the task that uses it, and the task's clock starts
# after placement and the image pull, which the state's timeout does not
# count against the job.
URL_START_ALLOWANCE_SECONDS = 600
CODEARTIFACT_TOKEN_SECONDS = 900  # the service's minimum

# collect's caps. A result.json is a list of short strings; anything near
# these is not one.
MAX_RESULT_BYTES = 256 * 1024
MAX_PROBES = 100
MAX_NAME = 64
MAX_OBSERVED = 200
MAX_DETAIL = 500
MAX_CAUSE = 500

RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# github-gateway's make_pr_id and scan.py's manual ids.
PR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# A run's time is the state's, but the job inside it is given less: the
# downloads before it and the uploads after it need the rest, and a job
# that overruns should still report rather than be stopped mid-upload.
STEP_TIMEOUT_MARGIN_SECONDS = 90
# collect's caps on a cdk-synth result.json's free text, all of it written
# by whatever ran.
MAX_LOG_TAIL = 4096
MAX_REASON = 500
CDK_STATUSES = {"ok", "failed", "unsupported", "error"}

# The leak test's DNS checks only mean something for names that DO resolve
# on the public internet: a name that exists nowhere fails inside the
# sandbox with or without a firewall. nip.io answers any name of the form
# <label>.<ip>.nip.io, and the query reaches its nameserver -- exactly the
# shape of an exfiltration lookup. collect confirms from outside the VPC
# that both names resolve there; if they do not, the check is inconclusive
# and fails (leak.py). The first deployed leak test passed a never-existing
# name while the firewall was detached, which is why (2026-10-10).
PUBLIC_NAME = "example.com"


def unique_dns_name(run_id, phase):
    return f"{run_id}-{phase}.127.0.0.1.nip.io"
# A run's tasks are found by their ECS task group. Step Functions' ECS
# integration does not accept StartedBy, the usual handle; it does accept
# Group, and DescribeTasks reports it.
GROUP_PREFIX = "sandbox:"

# Regional and virtual-hosted, so every URL names
# <bucket>.s3.<region>.amazonaws.com: a name the DNS Firewall allows and a
# path the gateway endpoint carries.
s3 = boto3.client(
    "s3",
    region_name=REGION,
    endpoint_url=f"https://s3.{REGION}.amazonaws.com",
    config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
)
codeartifact = boto3.client("codeartifact", region_name=REGION)
ecs = boto3.client("ecs", region_name=REGION)

_npm_endpoint = None


class BadRequest(ValueError):
    pass


def handler(event, context):
    action = event.get("action")
    if action == "prepare":
        return prepare(event)
    if action == "reap":
        return reap(event)
    if action == "collect":
        return collect(event)
    raise BadRequest(f"unknown action {action!r}")


# --- prepare -----------------------------------------------------------------

def _validate_request(event):
    kind = event.get("kind")
    if kind not in KINDS:
        raise BadRequest(f"kind must be one of {sorted(KINDS)}, not {kind!r}")
    phases = event.get("phases")
    if (not isinstance(phases, list) or not phases
            or any(p not in PHASES for p in phases) or len(set(phases)) != len(phases)):
        raise BadRequest(f"phases must be a non-empty list drawn from {list(PHASES)}")
    timeout = event.get("timeout_seconds")
    if (not isinstance(timeout, int) or isinstance(timeout, bool)
            or not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS):
        raise BadRequest(f"timeout_seconds must be an integer in "
                         f"[{MIN_TIMEOUT_SECONDS}, {MAX_TIMEOUT_SECONDS}]")
    phases = [p for p in PHASES if p in phases]
    synth = None
    if kind == "cdk-synth":
        synth = _validate_synth(event)
        if phases != list(PHASES):
            raise BadRequest("cdk-synth runs both phases: execute needs what fetch installs")
    # Always fetch-then-execute, whatever order the request listed.
    return kind, phases, timeout, synth


def _validate_synth(event):
    pr_id, app_dir, project_key = event.get("pr_id"), event.get("app_dir"), event.get("project_key")
    if not (isinstance(pr_id, str) and PR_ID_RE.match(pr_id)):
        raise BadRequest(f"pr_id {pr_id!r} is not a pull request's id")
    if not _app_dir_ok(app_dir):
        raise BadRequest(f"app_dir {app_dir!r} is not a repository path")
    # Only the project tarballs github-gateway writes, and only this PR's.
    if not (isinstance(project_key, str) and project_key.startswith(f"projects/{pr_id}/")
            and project_key.endswith(".tgz") and cdk._repo_path(project_key)):
        raise BadRequest(f"project_key {project_key!r} is not this pull request's project")
    return {"pr_id": pr_id, "app_dir": app_dir, "project_key": project_key}


def _app_dir_ok(app_dir):
    return app_dir == "." or (isinstance(app_dir, str) and cdk._repo_path(app_dir) is not None)


def run_key(run_id, phase, name):
    return f"runs/{run_id}/{phase}/{name}"


def _presign(method, bucket, key, expires):
    return s3.generate_presigned_url(
        "put_object" if method == "PUT" else "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expires,
    )


def _npm_repository_endpoint():
    global _npm_endpoint
    if _npm_endpoint is None:
        _npm_endpoint = codeartifact.get_repository_endpoint(
            domain=CODEARTIFACT_DOMAIN, domainOwner=CODEARTIFACT_OWNER,
            repository=CODEARTIFACT_NPM_REPO, format="npm",
        )["repositoryEndpoint"]
    return _npm_endpoint


def _codeartifact_token():
    return codeartifact.get_authorization_token(
        domain=CODEARTIFACT_DOMAIN, domainOwner=CODEARTIFACT_OWNER,
        durationSeconds=CODEARTIFACT_TOKEN_SECONDS,
    )["authorizationToken"]


def _env(pairs):
    # PascalCase, though ECS's own API spells these name/value: Step
    # Functions' ECS integration takes every parameter PascalCase, nested
    # ones included, and refuses the run otherwise (States.Runtime, found on
    # the first deployed run, 2026-10-09).
    return [{"Name": k, "Value": v} for k, v in pairs]


def _unavailable(kind, phases, timeout, synth):
    run_id = uuid.uuid4().hex
    logger.warning("sandbox is down: run %s (%s) not started", run_id, kind)
    return {
        "prepared": {
            "run_id": run_id, "group": GROUP_PREFIX + run_id, "kind": kind, "phases": phases,
            "run_fetch": False, "run_execute": False, "unavailable": True,
            "pr_id": (synth or {}).get("pr_id"), "app_dir": (synth or {}).get("app_dir"),
            "env": {},
        },
        "timeout_seconds": timeout,
        "tasks": {},
        "errors": {},
    }


def prepare(event):
    # The state machine sends the execution's whole input as `request`.
    kind, phases, timeout, synth = _validate_request(event.get("request", event))
    if not SANDBOX_ACTIVE:
        return _unavailable(kind, phases, timeout, synth)
    run_id = uuid.uuid4().hex
    expires = timeout + URL_START_ALLOWANCE_SECONDS
    npm_endpoint = _npm_repository_endpoint()

    if synth:
        # The task can reach this bucket and no other (spec §5), so the
        # project comes to it. github-gateway built the tarball from the
        # repository's own, under the same path rules as its snapshot.
        s3.copy_object(
            Bucket=SANDBOX_BUCKET, Key=run_key(run_id, "input", "project.tgz"),
            CopySource={"Bucket": ARTIFACTS_BUCKET, "Key": synth["project_key"]},
        )

    env = {}
    for phase in phases:
        manifest = {
            "RESULT_URL": _presign("PUT", SANDBOX_BUCKET, run_key(run_id, phase, "result.json"), expires),
            "OUTPUT_URL": _presign("PUT", SANDBOX_BUCKET, run_key(run_id, phase, "output.tgz"), expires),
            # Not a secret: the execute task probes that it cannot reach it.
            "CODEARTIFACT_HOST": urllib.parse.urlsplit(npm_endpoint).hostname,
        }
        if phase == "fetch":
            manifest["CODEARTIFACT_NPM_URL"] = npm_endpoint
            manifest["CODEARTIFACT_TOKEN"] = _codeartifact_token()
        if synth:
            manifest["APP_DIR"] = synth["app_dir"]
            manifest["SNAPSHOT_URL"] = _presign("GET", SANDBOX_BUCKET, run_key(run_id, "input", "project.tgz"), expires)
            manifest["STEP_TIMEOUT_SECONDS"] = max(MIN_TIMEOUT_SECONDS, timeout - STEP_TIMEOUT_MARGIN_SECONDS)
            if phase == "execute":
                # What fetch installed. Read-only here: execute's own
                # OUTPUT_URL is the only place it can write.
                manifest["DEPS_URL"] = _presign("GET", SANDBOX_BUCKET, run_key(run_id, "fetch", "output.tgz"), expires)
        if kind == "leak-test":
            # Valid, signed, and for a bucket the endpoint policy does not
            # admit: only that policy can make it fail.
            manifest["CANARY_URL"] = _presign("PUT", CANARY_BUCKET, f"{run_id}/{phase}", expires)
            # Another run's key with no signature at all.
            manifest["FOREIGN_URL"] = (f"https://{SANDBOX_BUCKET}.s3.{REGION}.amazonaws.com/"
                                       + run_key(uuid.uuid4().hex, phase, "result.json"))
            manifest["DNS_PUBLIC_NAME"] = PUBLIC_NAME
            manifest["DNS_UNIQUE_NAME"] = unique_dns_name(run_id, phase)
            manifest["ECR_REGISTRY"] = ECR_REGISTRY
            manifest["AWS_REGION_NAME"] = REGION

        manifest_key = run_key(run_id, phase, "manifest.json")
        s3.put_object(Bucket=SANDBOX_BUCKET, Key=manifest_key,
                      Body=json.dumps(manifest).encode("utf-8"), ContentType="application/json")
        env[phase] = _env([
            # Never SANDBOX_PHASE: the task definition fixes it, and an
            # override of the same name would win.
            ("SANDBOX_RUN_ID", run_id),
            ("SANDBOX_KIND", kind),
            ("MANIFEST_URL", _presign("GET", SANDBOX_BUCKET, manifest_key, expires)),
        ])

    logger.info("prepared run %s: kind=%s phases=%s timeout=%ss", run_id, kind, phases, timeout)
    return {
        "prepared": {
            "run_id": run_id,
            "group": GROUP_PREFIX + run_id,
            "kind": kind,
            "phases": phases,
            "run_fetch": "fetch" in phases,
            "run_execute": "execute" in phases,
            "unavailable": False,
            # null for the containment's own kinds; Collect's paths need
            # them present either way.
            "pr_id": (synth or {}).get("pr_id"),
            "app_dir": (synth or {}).get("app_dir"),
            "env": env,
        },
        "timeout_seconds": timeout,
        "tasks": {},
        "errors": {},
    }


# --- reap --------------------------------------------------------------------

def reap(event):
    group = event.get("group", "")
    if not (group.startswith(GROUP_PREFIX) and RUN_ID_RE.match(group[len(GROUP_PREFIX):])):
        raise BadRequest(f"group {group!r} is not a sandbox run's")
    arns = []
    for page in ecs.get_paginator("list_tasks").paginate(cluster=CLUSTER_ARN, desiredStatus="RUNNING"):
        arns += page["taskArns"]
    running = []
    # DescribeTasks takes at most 100 at a time.
    for i in range(0, len(arns), 100):
        tasks = ecs.describe_tasks(cluster=CLUSTER_ARN, tasks=arns[i:i + 100])["tasks"]
        running += [t["taskArn"] for t in tasks if t.get("group") == group]
    for arn in running:
        # A task still running after its state finished has outlived its
        # run; whatever it is doing, nothing will read it.
        ecs.stop_task(cluster=CLUSTER_ARN, task=arn, reason="sandbox-run: reaped after its state ended")
        logger.warning("reaped %s (%s)", arn, group)
    return {"stopped": running}


# --- collect -----------------------------------------------------------------

def _clip(value, limit):
    return value if len(value) <= limit else value[:limit] + "…"


def _read_result(run_id, phase, kind):
    """One phase's result.json, or why there is none. Never raises on
    what the task wrote: hostile content is a status, not an error."""
    key = run_key(run_id, phase, "result.json")
    try:
        head = s3.head_object(Bucket=SANDBOX_BUCKET, Key=key)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
            return {"status": "missing"}
        raise
    if head["ContentLength"] > MAX_RESULT_BYTES:
        return {"status": "oversized", "bytes": head["ContentLength"]}
    # Ranged, so a body that grew between the head and the get is still
    # read no further than the cap.
    body = s3.get_object(Bucket=SANDBOX_BUCKET, Key=key,
                         Range=f"bytes=0-{MAX_RESULT_BYTES - 1}")["Body"].read()
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"status": "malformed", "why": "not UTF-8 JSON"}
    return _shape(data, phase, kind)


def _shape(data, phase, kind):
    """Keep only the fields this function knows, at the sizes it allows."""
    if not isinstance(data, dict):
        return {"status": "malformed", "why": "not an object"}
    if data.get("phase") != phase or data.get("kind") != kind:
        return {"status": "malformed", "why": "phase or kind does not match the run"}
    if kind == "cdk-synth":
        return _shape_synth(data)
    probes = data.get("probes", [])
    if not isinstance(probes, list) or len(probes) > MAX_PROBES:
        return {"status": "malformed", "why": f"probes is not a list of at most {MAX_PROBES}"}
    clean, seen = [], set()
    for p in probes:
        if not (isinstance(p, dict) and isinstance(p.get("name"), str)
                and isinstance(p.get("observed"), str)):
            return {"status": "malformed", "why": "a probe without a string name and observation"}
        if len(p["name"]) > MAX_NAME or p["name"] in seen:
            return {"status": "malformed", "why": "a probe name too long or repeated"}
        seen.add(p["name"])
        entry = {"name": p["name"], "observed": _clip(p["observed"], MAX_OBSERVED)}
        if isinstance(p.get("detail"), str) and p["detail"]:
            entry["detail"] = _clip(p["detail"], MAX_DETAIL)
        clean.append(entry)
    return {"status": "ok", "result": {"probes": clean}}


def _shape_synth(data):
    status = data.get("status")
    if status not in CDK_STATUSES:
        return {"status": "malformed", "why": "a cdk-synth result without a known status"}
    exit_code, duration = data.get("exit_code"), data.get("duration_ms")
    result = {
        "status": status,
        "reason": _clip(data["reason"], MAX_REASON) if isinstance(data.get("reason"), str) else None,
        "exit_code": exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None,
        "duration_ms": duration if isinstance(duration, int) and not isinstance(duration, bool) else None,
        # The app's own output. Kept for whoever reads the run, and never
        # shown in a check run or the dashboard (spec §10, log_tail).
        "log_tail": data["log_tail"][-MAX_LOG_TAIL:] if isinstance(data.get("log_tail"), str) else "",
    }
    return {"status": "ok", "result": result}


def _task_summary(task):
    if not isinstance(task, dict):
        return None
    containers = []
    for c in task.get("containers") or []:
        containers.append({
            "name": c.get("Name"),
            "exit_code": c.get("ExitCode"),
            "last_status": c.get("LastStatus"),
            "reason": _clip(c.get("Reason") or "", MAX_CAUSE) or None,
        })
    return {"task_arn": task.get("task_arn"), "containers": containers}


def _error_summary(error):
    """A failed state's error, with the part worth reading first.

    When a task fails, Step Functions' Cause is the whole task description
    as JSON, and why it stopped comes late in it -- the first 500 characters
    are network attachments. So the stop code and reason are pulled out.
    """
    if not isinstance(error, dict):
        return None
    cause = error.get("Cause") or ""
    summary = {"error": error.get("Error")}
    try:
        task = json.loads(cause)
    except (ValueError, TypeError):
        task = None
    if isinstance(task, dict) and ("StoppedReason" in task or "StopCode" in task):
        summary["stop_code"] = task.get("StopCode")
        summary["stopped_reason"] = _clip(str(task.get("StoppedReason") or ""), MAX_CAUSE)
    else:
        summary["cause"] = _clip(cause, MAX_CAUSE)
    return summary


def _resolves(name):
    """From here, outside the sandbox's VPC: does the name resolve at all?"""
    try:
        socket.getaddrinfo(name, None)
        return "resolved"
    except OSError:
        return "dns-fail"


def collect(event):
    run_id = event.get("run_id", "")
    if not RUN_ID_RE.match(run_id):
        raise BadRequest(f"run_id {run_id!r} is not one prepare minted")
    kind = event.get("kind")
    tasks = event.get("tasks") or {}
    errors = event.get("errors") or {}

    phases = {}
    for phase in event.get("phases") or []:
        record = _read_result(run_id, phase, kind)
        record["task"] = _task_summary(tasks.get(phase))
        record["error"] = _error_summary(errors.get(phase))
        phases[phase] = record

    out = {"run_id": run_id, "kind": kind, "phases": phases, "reaped": (event.get("reap") or {}).get("stopped", [])}
    if kind == "cdk-synth":
        out["synth"] = _collect_synth(event, run_id, phases)
        logger.info("cdk-synth %s (%s): %s %s", run_id, out["synth"]["app_dir"],
                    out["synth"]["status"], out["synth"].get("reason") or "")
    if kind == "leak-test":
        public = _resolves(PUBLIC_NAME)
        outside = {phase: {"dns.example.com": public,
                           "dns.unique": _resolves(unique_dns_name(run_id, phase))}
                   for phase in phases}
        out["leak"] = leak.evaluate(phases, outside)
        logger.info("leak test %s: %s", run_id, "PASSED" if out["leak"]["passed"] else "FAILED")
    return out


# --- collect: cdk-synth --------------------------------------------------------

def _phase_problem(phases, phase, stage):
    """Why a phase gives synthesis nothing to use, or None if it does."""
    record = phases.get(phase) or {"status": "missing"}
    if record.get("error"):
        error = record["error"]
        why = error.get("stopped_reason") or error.get("cause") or error.get("error")
        return {"status": "error", "stage": stage,
                "reason": _clip(f"the {phase} task failed: {why}", MAX_REASON)}
    if record["status"] != "ok":
        return {"status": "error", "stage": stage,
                "reason": f"the {phase} task's result is {record['status']}"
                          + (f": {record['why']}" if record.get("why") else "")}
    result = record["result"]
    if result["status"] != "ok":
        return {"status": result["status"], "stage": stage,
                "reason": result.get("reason") or f"{phase} {result['status']}"}
    return None


def _collect_synth(event, run_id, phases):
    """One CDK app's outcome, and on success its templates in the scan
    prefix. Small, because the pipeline's state carries it."""
    pr_id, app_dir = event.get("pr_id"), event.get("app_dir")
    if not (isinstance(pr_id, str) and PR_ID_RE.match(pr_id)) or not _app_dir_ok(app_dir):
        raise BadRequest("a cdk-synth collect needs the pr_id and app_dir prepare checked")
    base = {"app_dir": app_dir, "templates": [], "stacks": []}
    if event.get("unavailable"):
        return {**base, "status": "unavailable", "stage": None,
                "reason": "the sandbox is switched off"}
    for phase, stage in (("fetch", "install"), ("execute", "synth")):
        problem = _phase_problem(phases, phase, stage)
        if problem:
            return {**base, **problem}

    key = run_key(run_id, "execute", "output.tgz")
    try:
        size = s3.head_object(Bucket=SANDBOX_BUCKET, Key=key)["ContentLength"]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
            return {**base, "status": "error", "stage": "synth",
                    "reason": "the synth reported success and uploaded nothing"}
        raise
    if size > cdk.MAX_ARCHIVE_BYTES:
        return {**base, "status": "rejected", "stage": "synth",
                "reason": f"the cloud assembly is over {cdk.MAX_ARCHIVE_BYTES // (1024 * 1024)}MB"}
    body = s3.get_object(Bucket=SANDBOX_BUCKET, Key=key,
                         Range=f"bytes=0-{cdk.MAX_ARCHIVE_BYTES - 1}")["Body"]
    try:
        files = cdk.read_archive(body)
        missing = cdk.missing_context(files)
        if missing:
            # The app synthesized against dummy values, so the templates are
            # not what would deploy. Report what to commit instead.
            return {**base, "status": "needs-context", "stage": "synth",
                    "reason": "lookups need a committed cdk.context.json: " + ", ".join(missing)}
        outputs, stacks = cdk.build(files, app_dir)
    except cdk.Hostile as e:
        return {**base, "status": "rejected", "stage": "synth", "reason": _clip(str(e), MAX_REASON)}

    for rel, data in sorted(outputs.items()):
        s3.put_object(Bucket=ARTIFACTS_BUCKET, Key=f"scans/{pr_id}/{rel}", Body=data,
                      ContentType="application/json")
    return {**base, "status": "ok", "stage": None, "reason": None,
            "templates": [s["template"] for s in stacks], "stacks": stacks}
