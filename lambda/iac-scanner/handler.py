"""iac-scanner Lambda (spec §4.1, §4.4 step 3; docs/multi-iac-spec.md).

Runs Trivy + Checkov against an IaC snapshot stored in S3 and writes raw
findings (status: "raw") to the DynamoDB findings table.

Terraform and OpenTofu today. One scanner rather than one per language
(multi-iac-spec §3): the split in §4.3 existed for Lambda's 250MB layer
ceiling, which the container image removed, and this one image already holds
every parser. Which languages are admitted is a deliberate list --
TRIVY_MISCONFIG_SCANNERS and CHECKOV_FRAMEWORKS -- not whatever the tools
would find, because a language whose suppression and deletion gates are not
implemented must not reach remediation (multi-iac-spec §4). Also used by
remediation-agent (spec §4.4 step 5) to self-check a proposed fix — that
call path passes persist=false and just reads the returned findings.

Every finding records two things about what it came from, because one field
could not answer both (multi-iac-spec §3.1):

  target_type    what to re-run to verify a fix -- terraform, opentofu
  finding_class  what kind of problem, and so which remediation path --
                 misconfiguration, secret, vulnerability

They do not derive from each other: a checkov secrets hit on a .tfvars file
is target_type "terraform" and finding_class "secret".

Event shape:
{
  "pr_id": "manual-1",
  "s3_prefix": "scans/manual-1/",   # snapshot under ARTIFACTS_BUCKET (see SNAPSHOT_SUFFIXES)
  "persist": true                    # optional, default true
}

There is no type parameter: the caller uploads a snapshot and the scanner
reports what it finds, per file. It took one until 2026-09-16, when it could
only be "terraform".

Each returned finding's "file" is relative to s3_prefix (e.g. "main.tf"), not
a local /tmp path -- callers can reconstruct the object's S3 key as
f"{s3_prefix}{finding['file']}".

Re-scanning a PR does not reset it. A finding id is a hash of
(source, rule, file, lines), so an id that fires again is the same finding
at the same place: the write refreshes what the scanner owns and leaves
status, control_mappings, proposed_fix and the review trail alone. An id
that stops firing is marked `no_longer_detected` rather than deleted --
nothing is silently decided (spec §8.1). See _write_findings.

Returns {pr_id, finding_count, findings, scan_errors, preserved_count,
no_longer_detected_count}. "scan_errors" lists files the scanner could not
parse. It is not cosmetic: a file that fails to
parse produces no findings, and remediation-agent's self-check reads "no
findings" as proof that a fix cleared its finding. A caller that ignores
scan_errors will read an unparseable file as a clean one. A tool that fails
outright (no output, or output that is neither JSON nor a recognised parse
error) raises ScannerError instead -- that is a scan that did not happen, not
a scan with a result.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TRIVY_BIN = "/opt/bin/trivy"
# Trivy wants somewhere writable for its cache even when nothing is fetched;
# /tmp is the only writable path in Lambda.
TRIVY_CACHE_DIR = "/tmp/trivy-cache"
# This project's own Rego checks, copied into the image next to the binary
# (Dockerfile). Loaded alongside the embedded bundle; Trivy only evaluates
# custom checks in the namespaces it is told to, hence --check-namespaces.
# What is here and why: checks/*.rego, each with its rationale in its
# metadata. They are admitted findings like any other rule (spec §8.1) and
# versioned with the image, so a scan stays reproducible.
TRIVY_CHECKS_DIR = "/opt/checks"
LAYER_PYTHON_PATH = "/opt/python"
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
METRIC_NAMESPACE = "IaCPosture"
# Checkov's own import is the dominant cost here, not the scan itself: it eagerly
# loads its full multi-framework check registry (~50-100s cold-start observed in
# testing), separate from the Lambda's own init phase. TODO: switch to importing
# checkov.terraform.runner.Runner in-process (skips checkov.main's non-Terraform
# framework loading, roughly halves this) instead of shelling out per-invocation.
SCAN_TIMEOUT_SECONDS = 240

# What a snapshot is. Both tools parse .tf.json natively, and both read
# .tfvars: Trivy auto-loads terraform.tfvars and *.auto.tfvars to resolve
# variables, and checkov's secrets framework scans them for literals.
#
# .tofu/.tofu.json are OpenTofu's, and are the same HCL -- Trivy parses them
# as terraform, including blocks Terraform itself rejects (measured, see
# multi-iac-spec §2). A directory holding both main.tf and main.tofu is
# scanned as both, which is not what OpenTofu does (it prefers .tofu and
# ignores the .tf); rare enough to leave, noted so it is not a surprise. Until
# 2026-09-12 this was .tf alone, which is exactly where a hardcoded password
# is *not* -- it is in the .tfvars that was never uploaded. scripts/scan.py
# and corpus/eval/run_eval.py upload the same set; keep the three aligned.
SNAPSHOT_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json", ".tofu", ".tofu.json")

# checkov frameworks. `secrets` is detect-secrets over every file in the
# snapshot: AWS key patterns, `password = "..."` assignments, high-entropy
# strings. It was off, so spec §2's "hardcoded secrets" goal measured 75% on
# the eval corpus with the miss being a literal RDS master password.
CHECKOV_FRAMEWORKS = "terraform,secrets"

# Trivy scans every config type it knows unless told otherwise, so this is
# the admission list and it is deliberately short. A language reaches
# remediation only once its suppression markers and structural guard exist
# (multi-iac-spec §4); until then, finding it would mean drafting fixes whose
# gates fail open. OpenTofu needs no entry -- Trivy reports .tofu as
# terraform.
TRIVY_MISCONFIG_SCANNERS = "terraform"
# The secrets runner only opens files on checkov's SUPPORTED_FILE_EXTENSIONS
# (.tf, .yml, .yaml, .json, .template, .bicep, .hcl) unless told to scan
# everything. .tfvars is not on that list, which is the one file a hardcoded
# password is most likely to be in. "All files" is bounded by
# _download_snapshot, so this is exactly SNAPSHOT_SUFFIXES and nothing else.
CHECKOV_SECRETS_ALL_FILES = "--enable-secret-scan-all-files"

# Trivy's Result.Class -> finding_class. Trivy already separates the two axes
# this project needs, which is where §3.1's design came from: Class says what
# kind of problem, Type says what was scanned.
TRIVY_CLASS_TO_FINDING_CLASS = {
    "config": "misconfiguration",
    "lang-pkgs": "vulnerability",
    "os-pkgs": "vulnerability",
    "secret": "secret",
}

# checkov's check_type is not one axis. Most values name a target
# ("terraform", "kubernetes"); these name a discipline instead, and the
# target has to come from the file itself.
CHECKOV_TYPE_TO_FINDING_CLASS = {
    "secrets": "secret",
    "sca_package": "vulnerability",
    "sca_image": "vulnerability",
}

# Where a suffix is more specific than the tool is. Trivy reports .tofu as
# "terraform" because it is the same HCL; a reviewer still wants to know
# which file they are looking at, and a repository can hold both. Longest
# suffix first, so .tofu.json does not match as .json would.
SUFFIX_TARGET_TYPES = (
    (".tofu.json", "opentofu"),
    (".tofu", "opentofu"),
    (".tf.json", "terraform"),
    (".tfvars.json", "terraform"),
    (".tfvars", "terraform"),
    (".tf", "terraform"),
)


def _target_type_for(file_path, reported):
    """The finding's target_type: the suffix where it is more specific than
    the tool, otherwise what the tool said."""
    for suffix, target in SUFFIX_TARGET_TYPES:
        if file_path.endswith(suffix):
            return target
    return reported or "unknown"


s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")


# Trivy reports an HCL parse failure as a log line on stderr, skips that file
# and scans the rest -- an improvement on tfsec, which abandoned the whole
# scan. The JSON on stdout says nothing about it, so stderr is the only place
# the failure is visible:
#   2026-09-12T16:44:07-07:00  ERROR  [terraform parser] Error parsing file
#   module="root" file_path="bad.tf" cause="..." err="bad.tf:1,30-31: Unclosed
#   configuration block; ..."
# Captured from trivy 0.74.0 on 2026-09-12. file_path is relative to the
# scanned directory. Trivy logs the same failure once per module that loads
# the file, hence the set in _run_trivy.
TRIVY_PARSE_ERROR_RE = re.compile(r'\[terraform parser\] Error parsing file.*?file_path="([^"]+)"')


class ScannerError(RuntimeError):
    """A scanner did not run to completion.

    Deliberately distinct from "the scanner ran and found nothing". Both used
    to arrive here as an empty list, and the difference matters more than
    anywhere else in this project: remediation-agent proves a fix by rescanning
    it and checking the finding no longer fires. A crashed, timed-out, or
    OOM-killed scanner reports zero findings, which that check reads as "the
    finding is gone" -- so swallowing a tool failure hands out a
    scanner-verified badge for a scan that never ran.
    """


def handler(event, context):
    pr_id = event["pr_id"]
    s3_prefix = event["s3_prefix"].rstrip("/") + "/"
    persist = event.get("persist", True)

    work_dir = f"/tmp/scan-{uuid.uuid4().hex}"
    os.makedirs(work_dir, exist_ok=True)

    try:
        downloaded = _download_snapshot(ARTIFACTS_BUCKET, s3_prefix, work_dir)
        if not downloaded:
            raise ValueError(f"no Terraform files found under s3://{ARTIFACTS_BUCKET}/{s3_prefix}")

        trivy_results, trivy_parse_errors = _run_trivy(work_dir)
        checkov_report = _run_checkov(work_dir)

        findings = _normalize_trivy(trivy_results, pr_id) + _normalize_checkov(checkov_report, pr_id)

        scan_errors = sorted(set(trivy_parse_errors) | set(_checkov_parse_errors(checkov_report, work_dir)))
        if scan_errors:
            # Reported, not raised: the other files in the snapshot scanned
            # fine and their findings are real. Raising would throw those away
            # over one bad file. It is the caller's job to decide what an
            # unscannable file means -- for remediation-agent's self-check it
            # is fatal, for a baseline scan it is a warning.
            logger.warning("could not parse %d file(s): %s", len(scan_errors), scan_errors)

        preserved = stale = 0
        if persist:
            preserved, stale = _write_findings(pr_id, findings)

        # Spec §4.1's findings-per-scan metric. Self-checks are excluded by
        # the persist flag: a rescan of one patched file is not a scan of a
        # PR, and counting it would make every remediation run look like a
        # burst of tiny scans.
        if persist:
            _emit_metrics(
                {"FindingsPerScan": len(findings), "ScanParseErrors": len(scan_errors)},
                {"Environment": ENVIRONMENT},
                pr_id=pr_id, event="scan_complete",
            )

        return {
            "pr_id": pr_id,
            "finding_count": len(findings),
            "findings": findings,
            "scan_errors": scan_errors,
            # How many distinct findings were already on this PR and kept
            # their review state, and how many previously-seen findings this
            # scan no longer reports. Both are 0 when persist is false, and
            # preserved_count is over distinct ids -- finding_count is what
            # the tools reported, which can name one id more than once.
            "preserved_count": preserved,
            "no_longer_detected_count": stale,
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _emit_metrics(metrics, dimensions, **context):
    """Publish CloudWatch metrics by printing one Embedded Metric Format line.

    print(), not logger: Lambda prefixes logger output with level, timestamp
    and request id, and EMF needs the whole log event to be the JSON object.
    CloudWatch extracts the metrics from the log stream, so this costs no IAM,
    no SDK call, and no extra latency -- and the line doubles as a structured
    record of the run. Namespace and dimension names are the contract with
    terraform/observability.tf; metric names are the contract with anyone
    graphing them.
    """
    print(json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [sorted(dimensions)],
                "Metrics": [{"Name": name, "Unit": "Count"} for name in metrics],
            }],
        },
        **dimensions,
        **metrics,
        **context,
    }))


def _download_snapshot(bucket, prefix, dest_dir):
    paginator = s3.get_paginator("list_objects_v2")
    downloaded = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(SNAPSHOT_SUFFIXES):
                continue
            rel_path = key[len(prefix):]
            local_path = os.path.join(dest_dir, rel_path)
            os.makedirs(os.path.dirname(local_path) or dest_dir, exist_ok=True)
            s3.download_file(bucket, key, local_path)
            downloaded.append(local_path)
    return downloaded


def _run_trivy(work_dir):
    """Returns (misconfigurations, parse_errors).

    Each misconfiguration is Trivy's own object plus the three things Trivy
    reports per Result rather than per finding: "Target" (the file, relative
    to work_dir), "Type" (terraform, kubernetes, ...) and "Class" (config,
    lang-pkgs, ...). The last two are the two axes a finding records.
    """
    proc = subprocess.run(
        [
            TRIVY_BIN, "config", work_dir,
            "--format", "json",
            # The checks embedded in the binary, never a registry fetch: no
            # egress from the function, and the rule set is pinned to the
            # layer's Trivy version, so a scan is reproducible.
            "--skip-check-update",
            "--misconfig-scanners", TRIVY_MISCONFIG_SCANNERS,
            "--cache-dir", TRIVY_CACHE_DIR,
            "--config-check", TRIVY_CHECKS_DIR,
            "--check-namespaces", "user",
        ],
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SECONDS,
    )
    # Trivy exits 0 whether or not it found issues (no --exit-code), so the
    # code says nothing. Empty stdout does: --format json always emits a
    # report object, even for an empty directory, so nothing at all means the
    # binary itself failed.
    if not proc.stdout.strip():
        raise ScannerError(
            f"trivy produced no output (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
        )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"trivy produced unparseable output: {proc.stdout[:500]}") from exc

    # Reported, not raised, for the same reason checkov's are: the caller
    # decides what an unscannable file means. The other files' findings are
    # real and are returned alongside.
    parse_errors = sorted(set(TRIVY_PARSE_ERROR_RE.findall(proc.stderr)))
    if parse_errors:
        logger.warning("trivy could not parse %s", parse_errors)

    results = []
    # A clean scan has no "Results" key at all; a scanned directory also gets
    # a Result for "." (the root module) that carries no misconfigurations.
    for result in report.get("Results") or []:
        for misconf in result.get("Misconfigurations") or []:
            results.append({
                **misconf,
                "Target": result.get("Target", ""),
                "Type": result.get("Type", ""),
                "Class": result.get("Class", ""),
            })
    return results, parse_errors


def _run_checkov(work_dir):
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    if LAYER_PYTHON_PATH not in existing.split(os.pathsep):
        env["PYTHONPATH"] = os.pathsep.join(p for p in (LAYER_PYTHON_PATH, existing) if p)
    # Avoids an unnecessary PyPI network call on every cold start.
    env["CKV_SKIP_PACKAGE_UPDATE_CHECK"] = "true"

    proc = subprocess.run(
        [sys.executable, "-m", "checkov.main", "-d", work_dir, "--framework", CHECKOV_FRAMEWORKS,
         CHECKOV_SECRETS_ALL_FILES, "-o", "json", "--compact"],
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SECONDS,
        env=env,
    )
    # checkov exits non-zero when it finds failed checks -- that's expected, not a failure.
    if not proc.stdout.strip():
        raise ScannerError(
            f"checkov produced no output (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"checkov produced unparseable output: {proc.stdout[:500]}") from exc


def _relativize_path(file_path, work_dir):
    """Strip the scratch directory back off a path a tool reported.

    Handles every form the tools emit: checkov's parsing_errors carry the
    absolute path, while its check records are already root-relative
    (/main.tf). Trivy reports everything relative to the scanned directory
    and does not need this. (tfsec, before it, echoed the absolute path in
    findings and dropped the leading slash in parse errors, which is why both
    prefix forms are still matched.)
    """
    for prefix in (work_dir.rstrip("/") + "/", work_dir.strip("/") + "/"):
        if file_path.startswith(prefix):
            return file_path[len(prefix):]
    return file_path.lstrip("/")


def _normalize_trivy(results, pr_id):
    now = datetime.now(timezone.utc).isoformat()
    findings = []
    for r in results:
        cause = r.get("CauseMetadata") or {}
        findings.append(_build_finding(
            pr_id=pr_id,
            source="trivy",
            # "AWS-0086". The tfsec long id this check used to be known by
            # (aws-s3-block-public-acls) is only an alias for ignore comments
            # and is not in the report; corpus/rule_mappings.json is keyed on
            # this form. "AVD-AWS-0086" is the same id with an older prefix.
            rule_id=r.get("ID", "unknown"),
            file_path=r.get("Target", ""),
            line_range=[cause.get("StartLine"), cause.get("EndLine")],
            severity=(r.get("Severity") or "UNKNOWN").upper(),
            target_type=_target_type_for(r.get("Target", ""), r.get("Type")),
            finding_class=TRIVY_CLASS_TO_FINDING_CLASS.get(r.get("Class"), "misconfiguration"),
            now=now,
        ))
    return findings


def _checkov_parse_errors(report, work_dir):
    """Files checkov could not parse, relative to work_dir.

    Both tools are consulted: Trivy says so on stderr (see
    TRIVY_PARSE_ERROR_RE), checkov reports the casualty here as data. Each
    skips the file and scans the rest, and each is the only source for a file
    that it alone cannot read -- the two parsers do not agree on every input.

    A file that fails to parse contributes no findings, so without this a
    syntactically broken .tf scans exactly like a compliant one -- and
    remediation-agent's self-check would read that as proof its fix worked.

    Absent "results" is checkov's shape for a report with nothing in it at all
    (see Report.get_dict / is_empty upstream); parsing errors would themselves
    make the report non-empty, so that shape means zero parse errors, not
    unknown.
    """
    parse_errors = [
        path for r in _checkov_reports(report)
        for path in ((r.get("results") or {}).get("parsing_errors") or [])
    ]
    return sorted({_relativize_path(path, work_dir) for path in parse_errors})


def _checkov_reports(report):
    """checkov's JSON is one report object when a single framework had
    anything to say and a list of them when more than one did (see
    runner_registry upstream: a lone report is unwrapped, several are not).
    With `terraform,secrets` both shapes occur -- a list whenever a secret
    fires, a dict otherwise -- so every consumer goes through here."""
    if isinstance(report, list):
        return report
    return [report]


def _normalize_checkov(report, pr_id):
    now = datetime.now(timezone.utc).isoformat()
    findings = []
    # Per report rather than flattened, because check_type lives on the
    # report and is half of what a finding records.
    for r in _checkov_reports(report):
        check_type = r.get("check_type") or ""
        finding_class = CHECKOV_TYPE_TO_FINDING_CLASS.get(check_type, "misconfiguration")
        for c in ((r.get("results") or {}).get("failed_checks") or []):
            # checkov reports paths root-relative to the scanned dir (/main.tf).
            file_path = c.get("file_path", "").lstrip("/")
            findings.append(_build_finding(
                pr_id=pr_id,
                source="checkov",
                rule_id=c.get("check_id", "unknown"),
                file_path=file_path,
                line_range=list(c.get("file_line_range") or [None, None]),
                severity=(c.get("severity") or "UNKNOWN").upper(),
                # "secrets" names a discipline, not a target, so the target
                # comes from the file -- a password in a .tfvars is a secret
                # found in Terraform.
                target_type=_target_type_for(
                    file_path, "" if check_type in CHECKOV_TYPE_TO_FINDING_CLASS else check_type
                ),
                finding_class=finding_class,
                now=now,
            ))
    return findings


def _build_finding(pr_id, source, rule_id, file_path, line_range, severity,
                   target_type, finding_class, now):
    # Deterministic id, so re-scanning the same PR recognises a finding it has
    # seen before rather than accumulating duplicates. Because the id hashes
    # the location as well as the rule, an id that fires again is the same
    # rule in the same place -- which is what lets _write_findings keep that
    # finding's review state without comparing anything else.
    finding_key = f"{source}:{rule_id}:{file_path}:{line_range}"
    finding_id = hashlib.sha1(finding_key.encode()).hexdigest()[:16]
    return {
        "pk": f"PR#{pr_id}",
        "sk": f"FINDING#{finding_id}",
        "finding_id": finding_id,
        "target_type": target_type,
        "finding_class": finding_class,
        "source": source,
        "rule_id": rule_id,
        "file": file_path,
        "line_range": line_range,
        "severity": severity,
        "control_mappings": [],
        "status": "raw",
        "proposed_fix": None,
        "created_at": now,
        "updated_at": now,
    }


def _write_findings(pr_id, findings):
    """Persist this scan without discarding what humans and agents decided.

    Returns (preserved, no_longer_detected).

    A plain put_item overwrote the whole record, so every re-scan reset each
    finding that still fired to status "raw" with no mapping and no proposed
    fix -- reviewed, resolved or not. That cost the mapping bill again on
    every run, forced a redraft-only run to bypass the pipeline
    (scripts/scan.py --stages remediate), and would have made v3 impossible:
    a GitHub App re-scans on every push, and a push cannot erase the review
    of the push before it.

    So each finding is an update, not a put, and the fields divide in two:

      scanner-owned   severity, last_seen_at, updated_at -- always refreshed,
                      because the tool is the authority on them
      decided         status, control_mappings, proposed_fix, created_at --
                      written only if absent (if_not_exists), because a human
                      or an agent owns them

    The other half of a re-scan is a finding that has stopped firing. It is
    marked, not deleted: the fix may have landed, the file may have been
    removed, or a tool upgrade may have dropped the rule, and those read the
    same from here. Deleting would also take the audit trail with it, and
    spec §8.1's rule is that nothing is silently decided. A finding that
    fires again has the mark removed.

    Findings are deduplicated by id first. A finding id hashes
    (source, rule, file, lines) but not the resource address, so one rule
    firing on several resources that share a reported line range collapses
    to one id -- on PugetScope's ecr module, four repositories declared in
    one block give `AWS-0031` four times at the same lines. The table can
    hold one record per id either way (the previous batch_writer silently
    took the last), so this only makes the write and the counts match what
    is stored. Separating them means putting the resource address in the
    hash, which renumbers every id in the table and needs a migration.
    """
    table = dynamodb.Table(DYNAMODB_TABLE)
    now = datetime.now(timezone.utc).isoformat()

    known = _existing_finding_ids(table, pr_id)
    unique = _deduplicate(findings)
    preserved = len(known & set(unique))
    for finding in unique.values():
        table.update_item(
            Key={"pk": finding["pk"], "sk": finding["sk"]},
            UpdateExpression=(
                "SET finding_id = :finding_id, target_type = :target_type, "
                "finding_class = :finding_class, "
                "#source = :source, rule_id = :rule_id, #file = :file, "
                "line_range = :line_range, severity = :severity, "
                "last_seen_at = :now, updated_at = :now, "
                "created_at = if_not_exists(created_at, :now), "
                "#status = if_not_exists(#status, :raw), "
                "control_mappings = if_not_exists(control_mappings, :empty), "
                "proposed_fix = if_not_exists(proposed_fix, :null) "
                # It fired, so any previous mark is wrong now. iac_type is
                # the field target_type and finding_class replaced on
                # 2026-09-16; dropping it here is what migrates a record the
                # first time it is re-scanned.
                "REMOVE no_longer_detected, iac_type"
            ),
            ExpressionAttributeNames={"#source": "source", "#file": "file", "#status": "status"},
            ExpressionAttributeValues={
                ":finding_id": finding["finding_id"],
                ":target_type": finding["target_type"],
                ":finding_class": finding["finding_class"],
                ":source": finding["source"],
                ":rule_id": finding["rule_id"],
                ":file": finding["file"],
                ":line_range": finding["line_range"],
                ":severity": finding["severity"],
                ":now": now,
                ":raw": "raw",
                ":empty": [],
                ":null": None,
            },
        )

    stale = known - set(unique)
    for finding_id in sorted(stale):
        table.update_item(
            Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{finding_id}"},
            UpdateExpression="SET no_longer_detected = :now",
            # Only the first scan that stops seeing it records when that
            # happened; a later scan must not move the date forward.
            ConditionExpression="attribute_not_exists(no_longer_detected)",
            ExpressionAttributeValues={":now": now},
        )
    if stale:
        logger.info("%d finding(s) no longer detected on %s: %s", len(stale), pr_id, sorted(stale))
    return preserved, len(stale)


def _deduplicate(findings):
    """{finding_id: finding}, keeping the first of any colliding pair.

    The returned finding list is NOT deduplicated: remediation-agent's
    self-check counts occurrences of a (source, rule_id) pair to tell "one of
    three instances was fixed" from "none were", and collapsing them would
    break that comparison.
    """
    unique = {}
    for finding in findings:
        unique.setdefault(finding["finding_id"], finding)
    return unique


def _existing_finding_ids(table, pr_id):
    """Every finding id already recorded against this PR.

    Read before the writes, so "already there" means before this scan.
    Projected to the id alone -- a PR's findings carry whole file diffs, and
    none of that is needed to answer this question.
    """
    ids = set()
    kwargs = {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :sk_prefix)",
        "ExpressionAttributeValues": {":pk": f"PR#{pr_id}", ":sk_prefix": "FINDING#"},
        "ProjectionExpression": "finding_id",
    }
    while True:
        response = table.query(**kwargs)
        ids.update(item["finding_id"] for item in response.get("Items", []) if "finding_id" in item)
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return ids
        kwargs["ExclusiveStartKey"] = last_key
