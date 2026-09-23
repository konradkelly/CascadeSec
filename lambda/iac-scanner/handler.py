"""iac-scanner Lambda (spec §4.1, §4.4 step 3; docs/multi-iac-spec.md).

Runs Trivy + Checkov + KICS against an IaC snapshot stored in S3 and writes
raw findings (status: "raw") to the DynamoDB findings table. Which tool covers
what is not uniform and is not meant to be: Trivy takes Terraform and
Kubernetes, checkov takes all four, and KICS takes ARM and Bicep, where it is
the only one of the three that reads both correctly.

Terraform, OpenTofu, Kubernetes, ARM and Bicep today. One scanner rather than
one per language (multi-iac-spec §3): the split in §4.3 existed for Lambda's
250MB layer ceiling, which the container image removed, and this one image
already holds every parser. Which languages are admitted is a deliberate list --
TRIVY_MISCONFIG_SCANNERS and CHECKOV_FRAMEWORKS -- not whatever the tools
would find, because a language whose suppression and deletion gates are not
implemented must not reach remediation (multi-iac-spec §4). Also used by
remediation-agent (spec §4.4 step 5) to self-check a proposed fix — that
call path passes persist=false and just reads the returned findings.

Every finding records two things about what it came from, because one field
could not answer both (multi-iac-spec §3.1):

  target_type    what to re-run to verify a fix -- terraform, opentofu,
                 kubernetes, arm, bicep
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
parse -- what each tool reported, plus what this scanner checked itself,
because for some languages neither tool reports anything at all (see
_unparseable_admitted_files). It is not cosmetic: a file that fails to
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
import tempfile
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
KICS_BIN = "/opt/bin/kics"
# KICS's query bundle and its Rego libraries, copied out of the published
# image (Dockerfile). Passed explicitly because the binary's defaults are
# relative to its own working directory, which is not where it lives here.
KICS_ASSETS_DIR = "/opt/kics-assets"
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
# .yaml/.yml are Kubernetes manifests, added 2026-09-20. Unlike every other
# suffix here the extension does not say what the file is: a .yaml is a
# manifest, a Helm template, a CloudFormation stack, a CI workflow or none of
# them. Nothing pre-classifies it -- the admission lists below do, and both
# tools were measured on a directory holding all five (2026-09-20): each
# reported only the Kubernetes manifest and skipped the rest silently, with
# no parse error and nothing on stderr. So a repository full of unrelated
# YAML costs a download and nothing else. scripts/scan.py already uploaded
# these for context-agent, so the snapshot does not change shape; what
# changes is that the scanner now opens them.
#
# .tofu/.tofu.json are OpenTofu's, and are the same HCL -- Trivy parses them
# as terraform, including blocks Terraform itself rejects (measured, see
# multi-iac-spec §2). A directory holding both main.tf and main.tofu is
# scanned as both, which is not what OpenTofu does (it prefers .tofu and
# ignores the .tf); rare enough to leave, noted so it is not a surprise. Until
# 2026-09-12 this was .tf alone, which is exactly where a hardcoded password
# is *not* -- it is in the .tfvars that was never uploaded. scripts/scan.py
# and corpus/eval/run_eval.py upload the same set; keep the three aligned.
# .bicep joined on 2026-09-22, with ARM. Bicep is checkov-only -- Trivy has
# no Bicep scanner -- so its self-check compares one source rather than two,
# which is the mirror of OpenTofu being Trivy-only and is said on the badge
# rather than left to be discovered (dashboard/src/review/coverage.ts).
SNAPSHOT_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json", ".tofu", ".tofu.json",
                     ".yaml", ".yml", ".bicep")

# ARM templates are .json, and that is the .yaml ambiguity again but worse: a
# .json is a deployment template, a lockfile, a tsconfig, a CI config or none
# of them, and a repository holds far more of the others. Admitting the suffix
# would download every one and hand it to checkov's secrets runner, which is
# given --enable-secret-scan-all-files.
#
# So ARM is admitted by content: a top-level $schema naming a
# deploymentTemplate, which every ARM template declares about itself. A
# filename convention was the alternative and is measurably worse -- on
# Azure/azure-quickstart-templates (2026-09-22) the tree holds 519 .json files
# of which 175 are templates, and 159 of the remainder are
# azuredeploy.parameters.json: files a name-based rule admits and this one does
# not. Nothing outside the 175 sniffed as ARM.
#
# Must match the copies in scripts/scan.py, corpus/eval/run_eval.py and
# corpus/external/run_external.py; corpus/test_corpus.py asserts all four agree.
ARM_SCHEMA_RE = re.compile(r'"\$schema"\s*:\s*"[^"]*deploymentTemplate\.json')

# CloudFormation's equivalent, and the second language admitted by content.
# A .json template is the same problem ARM posed -- the suffix says nothing --
# with one extra turn: ARM already claimed `.json` in SUFFIX_TARGET_TYPES on
# the strength of being the only content-admitted language, so admitting this
# one means the suffix can no longer decide either. _json_template_verdict is
# where both are decided now, and _target_type_for reads its answer.
#
# `AWSTemplateFormatVersion` is what a template declares about itself, as
# `$schema` is for ARM -- but unlike `$schema` it is OPTIONAL, so the parsed
# fallback in _is_cfn_document carries real weight rather than being a
# belt-and-braces second check. A template without it is ordinary (cdk synth
# omits it), which is why the fallback exists at all.
CFN_MARKER_RE = re.compile(r'"AWSTemplateFormatVersion"\s*:')
# The second cheap gate, and it is not optional. AWSTemplateFormatVersion is
# the declaration a template *may* carry; a version-less template is ordinary
# (cdk synth writes one), and with only the marker above the parsed fallback
# in _is_cfn_document could never be reached to catch it -- the regex gate
# would have returned "other" first. Caught by its own test rather than in
# production, which is the whole point of having written that test.
#
# Cheap in the same way the marker is: a resource type in one of
# CloudFormation's namespaces is a string no lockfile carries, so json.loads
# is still never called on a 4MB file that is not a template.
CFN_RESOURCE_TYPE_RE = re.compile(r'"Type"\s*:\s*"(?:AWS|Alexa|Custom)::')
# The namespaces a CloudFormation resource type can sit in. AWS:: is the bulk,
# Custom:: is a custom resource backed by a Lambda, and Alexa::ASK::Skill is
# the one first-party type outside AWS::. A module's type ends `::MODULE` but
# still begins AWS::, so it needs no entry.
CFN_TYPE_NAMESPACES = frozenset({"AWS", "Alexa", "Custom"})

# checkov frameworks. `secrets` is detect-secrets over every file in the
# snapshot: AWS key patterns, `password = "..."` assignments, high-entropy
# strings. It was off, so spec §2's "hardcoded secrets" goal measured 75% on
# the eval corpus with the miss being a literal RDS master password.
CHECKOV_FRAMEWORKS = "terraform,kubernetes,arm,bicep,cloudformation,secrets"

# Trivy scans every config type it knows unless told otherwise, so this is
# the admission list and it is deliberately short. A language reaches
# remediation only once its suppression markers and structural guard exist
# (multi-iac-spec §4); until then, finding it would mean drafting fixes whose
# gates fail open. OpenTofu needs no entry -- Trivy reports .tofu as
# terraform.
#
# kubernetes added 2026-09-20, with its gates built first: the annotation
# marker and the YAML structural guard landed in remediation-agent on
# 2026-09-19, the CIS Kubernetes corpus on the same day, and the eval cases
# with this change. `helm` is deliberately NOT here even though Trivy
# supports it and the chart files are already in the snapshot -- see
# multi-iac-spec §6 step 3. Two reasons, and the second is the blocking one:
# rendering a chart executes its templates, and the self-check scans one
# corrected file in isolation, where a template without its Chart.yaml and
# values.yaml renders nothing at all. No findings on a rescan is exactly what
# this pipeline reads as "the fix worked", so enabling helm would make the
# self-check fail open on every chart. Measured on a chart in the same mixed
# directory: with helm off, Trivy skips the template silently rather than
# reporting a parse error.
# azure-arm was here from 2026-09-22 and was removed again on 2026-09-23,
# which is the only time a language has been taken back off this list. Trivy's
# ARM adapter does not populate the fields several of its own checks read --
# `accountreplicationtype` comes back empty on a template declaring
# `Standard_GRS`, because it reads `properties` and not its sibling `sku` --
# so four rules could never pass on a template however it was written, and
# they were a third of its ARM output. The full measurement and the upstream
# report are in docs/trivy-azure-arm-adapter-gap.md. KICS reads ARM correctly
# and is what scans it now; Trivy keeps Terraform and Kubernetes, where it is
# the better of the two tools. Revisit if the adapter is fixed.
# cloudformation added 2026-09-23. Measured on a directory holding a
# manifest, both template syntaxes, an ARM template, a tsconfig and a CI
# workflow: the manifest reported the same 18 KSV rules with the scanner on
# as off, both templates reported the same 10 AWS-* rules, and nothing
# claimed the other three. So enabling it costs no cross-talk with the
# Kubernetes admission that shares the .yaml suffix.
TRIVY_MISCONFIG_SCANNERS = "terraform,kubernetes,cloudformation"

# KICS's platform names. AzureResourceManager covers both ARM templates and
# Bicep -- unlike Trivy, KICS parses .bicep natively, which is what gives
# Bicep a second source and retired the single-source caveat multi-iac-spec §4
# carried for it. CloudFormation joined 2026-09-23 and is a third source for
# that language rather than a second: Trivy and checkov both read it too.
# Measured the same day on the mixed directory: KICS parsed 3 files and failed
# none, attributing them to exactly the platform each belongs to.
KICS_PLATFORMS = ("AzureResourceManager", "CloudFormation")
# The secrets runner only opens files on checkov's SUPPORTED_FILE_EXTENSIONS
# (.tf, .yml, .yaml, .json, .template, .bicep, .hcl) unless told to scan
# everything. .tfvars is not on that list, which is the one file a hardcoded
# password is most likely to be in. "All files" is bounded by
# _download_snapshot, so this is exactly the admitted set and nothing else --
# which is why a .json that sniffs as neither template language is deleted
# from work_dir rather than merely left off the returned list: this runner
# reads the directory, not our list.
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
    (".bicep", "bicep"),
    # `.json` and `.template` are deliberately NOT here. Until 2026-09-23 a
    # bare .json mapped to "arm" unconditionally, which was sound while ARM
    # was the only content-admitted language: such a file was in the snapshot
    # only because it sniffed as a deployment template, so the mapping was
    # true by construction of the download filter rather than by guess.
    # CloudFormation breaks that construction -- a .json in the snapshot is
    # now an ARM template OR a CloudFormation one -- so the classification
    # moves to the content sniff that admitted the file, threaded here as
    # `classifications`. Leaving the old entry in place would have labelled
    # every CloudFormation .json "arm": the wrong structural guard, the wrong
    # suppression dialect and the wrong dashboard group, and for KICS findings
    # it would have hit every finding rather than only the secrets path,
    # because _normalize_kics passes no `reported` at all.
)

# Where the two tools name one target differently. Trivy's scanner name for
# ARM is "azure-arm"; checkov's check_type is "arm". A finding must carry one
# name and not two: remediation-agent dispatches its structural guard on this
# field and the dashboard groups drafted fixes by it, so two spellings would
# be two groups and one unguarded language.
REPORTED_TARGET_TYPES = {"azure-arm": "arm"}


def _target_type_for(file_path, reported, classifications=None):
    """The finding's target_type, from the most reliable source available.

    In order: a suffix that is more specific than the tool (.tofu is
    "opentofu" where Trivy says "terraform"); then what the content sniff
    decided when the file was admitted, which is the only thing that can tell
    an ARM .json from a CloudFormation one; then what the tool reported.

    The sniff outranks the tool because the one path that needs it has no
    tool answer to use: checkov reports check_type "secrets" for a literal in
    a template, which names a discipline and not a target, and
    _normalize_kics passes no `reported` whatsoever. Where both exist they
    agree -- measured 2026-09-23, all three tools attribute each template to
    its own language.
    """
    for suffix, target in SUFFIX_TARGET_TYPES:
        if file_path.endswith(suffix):
            return target
    sniffed = (classifications or {}).get(file_path.lstrip("./"))
    if sniffed:
        return sniffed
    reported = reported or ""
    return REPORTED_TARGET_TYPES.get(reported, reported) or "unknown"


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
#
# The parser tag is matched generically rather than as the literal
# "terraform", so a second language's parse failure is not invisible here by
# construction. --misconfig-scanners bounds which parsers can run at all, so
# this cannot pick up noise from a language we do not scan.
#
# It is a widening and not a fix: measured 2026-09-22, Trivy emits no parse
# error at all for a broken ARM template or a broken Kubernetes manifest --
# stderr is silent and the file simply does not appear in "Detected config
# files". Trivy's parse-error logging is Terraform-only in practice, which is
# why _unparseable_admitted_files exists rather than a longer regex.
TRIVY_PARSE_ERROR_RE = re.compile(
    r'\[[a-z0-9_-]+ parser\] Error parsing file.*?file_path="([^"]+)"')

# A Go template delimiter. A Helm chart template is not valid YAML until it
# is rendered, and helm is deliberately not admitted (see
# TRIVY_MISCONFIG_SCANNERS), so a template that does not parse is not a file
# this scanner failed to read -- it is a file this scanner does not handle.
# Measured on a mixed directory 2026-09-20: with helm off, both tools skip a
# chart template silently and the cost of leaving it out is zero noise.
# Reporting one here would turn that into noise on every repository that
# carries a chart, and two of the external baselines carry one.
GO_TEMPLATE_RE = re.compile(r"\{\{")

# CloudFormation's short-form intrinsics, which are YAML tags and not YAML
# syntax: `BucketName: !Sub '${AWS::StackName}-logs'`. A stock PyYAML has no
# constructor for them, so safe_load raises ConstructorError -- a YAMLError
# subclass, which is what _unparseable_admitted_files catches.
#
# That made every CloudFormation template written in the idiomatic style an
# "unparseable admitted file" from the day .yaml was admitted (2026-09-20),
# long before CloudFormation itself was on the list: a .yaml is downloaded
# whatever it turns out to be. The direction of that failure is the safe one
# -- a scan error holds a fix for review rather than passing it -- but it is
# still a file this scanner CAN read being reported as one it cannot, and it
# would block remediation across the whole language the moment CloudFormation
# is admitted. Measured against PyYAML as shipped: `!Sub` raises
# "could not determine a constructor for the tag '!Sub'".
#
# Enumerated rather than matched as a `!`-prefix multi-constructor, which is
# the shorter version of this and the wrong one: a prefix rule accepts any
# tag at all, so a genuinely broken file carrying `!Whatever` would parse and
# this check would under-report. Under-reporting is the failure the check
# exists to prevent. This is a closed, documented set, and one the tools that
# read the template already agree on.
CFN_INTRINSIC_TAGS = (
    "!Ref", "!Sub", "!GetAtt", "!GetAZs", "!ImportValue", "!Join", "!Select",
    "!Split", "!FindInMap", "!Base64", "!Cidr", "!Transform", "!If", "!Not",
    "!And", "!Or", "!Equals", "!Condition",
)


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
        downloaded, unreadable_templates, classifications = _download_snapshot(
            ARTIFACTS_BUCKET, s3_prefix, work_dir)
        if not downloaded:
            raise ValueError(f"no IaC files found under s3://{ARTIFACTS_BUCKET}/{s3_prefix}")

        trivy_results, trivy_parse_errors = _run_trivy(work_dir)
        checkov_report = _run_checkov(work_dir)
        kics_report = _run_kics(work_dir)

        findings = (
            _normalize_trivy(trivy_results, pr_id, classifications)
            + _normalize_checkov(checkov_report, pr_id, classifications)
            + _normalize_kics(kics_report, work_dir, pr_id, classifications)
        )

        kics_unparsed = _kics_unparsed_count(kics_report)
        if kics_unparsed:
            # A count without names, so it cannot join scan_errors. ARM and
            # Bicep are covered there by _json_template_verdict and checkov anyway; this
            # is here so the gap is visible in the log.
            logger.warning("kics opened %d file(s) it could not parse", kics_unparsed)

        scan_errors = sorted(
            set(trivy_parse_errors)
            | set(_checkov_parse_errors(checkov_report, work_dir))
            # The languages neither tool reports on. Not redundant with the
            # two above: see _unparseable_admitted_files.
            | set(_unparseable_admitted_files(downloaded, work_dir))
            # An admitted .json that claims the ARM schema and will not parse.
            # This one is ours, produced by json.loads, and does not depend on
            # either tool choosing to report -- which for ARM neither does.
            | set(unreadable_templates)
        )
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


def _json_template_verdict(text):
    """"arm" | "cloudformation" | "other" | "unreadable", for a .json or
    .template in the snapshot.

    Two languages are now admitted by content rather than by name, and one
    function decides between them so that the two sniffs cannot drift into
    overlapping. Measured over the whole azure-quickstart-templates tree
    (4849 .json, 2026-09-23): 1887 sniff as ARM, 0 as CloudFormation, 0 as
    both. The exclusivity is structural rather than lucky -- an ARM template
    is identified by a `$schema` it declares about itself, a CloudFormation
    template by `AWSTemplateFormatVersion` or by resource types in the
    `AWS::`/`Alexa::`/`Custom::` namespaces, and neither vocabulary appears in
    the other.

    "unreadable" is the dangerous value and the reason there are four rather
    than three. A .json that will not parse might be a truncated lockfile, or
    it might be the template a fix just broke -- and dropping the second
    silently is the fail-open multi-iac-spec §4 names: no findings is exactly
    what the self-check reads as "the fix worked". So one that still carries
    either language's marker text is reported as a scan error rather than
    discarded, and one that does not was never our file.

    The regexes run first so json.loads is never called on a 4MB lockfile,
    and the parsed checks run second so a marker string sitting in some other
    file's data cannot admit it.
    """
    looks_arm = bool(ARM_SCHEMA_RE.search(text))
    looks_cfn = bool(CFN_MARKER_RE.search(text) or CFN_RESOURCE_TYPE_RE.search(text))
    if not looks_arm and not looks_cfn:
        return "other"
    try:
        doc = json.loads(text)
    except ValueError:
        return "unreadable"
    if not isinstance(doc, dict):
        return "other"
    schema = doc.get("$schema")
    if isinstance(schema, str) and "deploymentTemplate.json" in schema:
        return "arm"
    return "cloudformation" if _is_cfn_document(doc) else "other"


def _is_cfn_document(doc):
    """Whether a parsed JSON object is a CloudFormation template.

    `AWSTemplateFormatVersion` is the declaration, and it is what CFN_MARKER_RE
    looks for -- but it is optional in CloudFormation, so a template that
    omits it still has to be recognised. The fallback is the `Resources`
    mapping: every entry carrying a `Type` in one of CloudFormation's own
    namespaces. Requiring *every* entry rather than any keeps an unrelated
    document that happens to hold one such string from being admitted.
    """
    if "AWSTemplateFormatVersion" in doc:
        return True
    resources = doc.get("Resources")
    if not isinstance(resources, dict) or not resources:
        return False
    return all(
        isinstance(body, dict)
        and isinstance(body.get("Type"), str)
        and body["Type"].split("::")[0] in CFN_TYPE_NAMESPACES
        for body in resources.values()
    )


def _download_snapshot(bucket, prefix, dest_dir):
    """Returns (downloaded, unreadable_templates, classifications).

    ARM was the first language whose admission could not be decided from the
    key, and CloudFormation is the second. The listing carries no content, so
    the only place to sniff is after the GET: a .json that is neither is
    *removed from dest_dir*, not merely left off the returned list, because
    checkov's secrets runner reads the directory rather than our list. Our own
    uploaders apply the same predicate locally and for free, so in practice
    little extra comes down; this is the backstop for a snapshot written by
    anything else.

    `classifications` is what the sniff decided, keyed by the path relative to
    the prefix -- the same spelling the tools report a finding's file under,
    so _target_type_for can look a finding up. It is the only thing that can
    tell an ARM .json from a CloudFormation one after the fact, since the two
    share a suffix and checkov's secrets runner and KICS both report findings
    without naming a target.
    """
    paginator = s3.get_paginator("list_objects_v2")
    downloaded, unreadable_templates, classifications = [], [], {}
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            admitted = key.endswith(SNAPSHOT_SUFFIXES)
            # .template is checkov's own extension for a CloudFormation
            # template and says nothing on its own, so it is sniffed like a
            # .json rather than admitted on the name.
            sniff_candidate = key.endswith((".json", ".template"))
            if not admitted and not sniff_candidate:
                continue
            rel_path = key[len(prefix):]
            local_path = os.path.join(dest_dir, rel_path)
            os.makedirs(os.path.dirname(local_path) or dest_dir, exist_ok=True)
            s3.download_file(bucket, key, local_path)
            # An admitted suffix that is also sniffable (.tf.json, .tofu.json,
            # .tfvars.json) is Terraform's and already named by its suffix;
            # SUFFIX_TARGET_TYPES claims those before the sniff is consulted.
            if admitted:
                downloaded.append(local_path)
                continue
            try:
                with open(local_path, encoding="utf-8") as fh:
                    verdict = _json_template_verdict(fh.read())
            except (OSError, UnicodeDecodeError):
                verdict = "other"
            if verdict in ("arm", "cloudformation"):
                downloaded.append(local_path)
                classifications[rel_path.replace(os.sep, "/")] = verdict
                continue
            os.remove(local_path)
            if verdict == "unreadable":
                unreadable_templates.append(rel_path.replace(os.sep, "/"))
    return downloaded, unreadable_templates, classifications


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


def _run_kics(work_dir):
    """Returns KICS's parsed report for the ARM and Bicep files in work_dir.

    KICS writes its report to a directory rather than stdout, so one is made
    alongside the scan and read back.

    No egress, like the other two: --disable-full-descriptions stops the one
    call KICS would otherwise make to fetch rule descriptions, and the queries
    come from the bundle copied into the image. Verified under `--network
    none` on 2026-09-23.

    A scan that finds nothing still writes a report, so a missing file means
    the binary itself failed -- the same reasoning as Trivy's empty stdout.
    """
    # Its own directory rather than one inside work_dir: the report is a
    # .json, and a .json inside the scanned tree is a file the next scan --
    # or this one -- would try to read as an ARM template. mkdtemp honours
    # TMPDIR, which is /tmp in Lambda, the only writable path there.
    report_dir = tempfile.mkdtemp(prefix="kics-")
    try:
        proc = subprocess.run(
            [
                KICS_BIN, "scan",
                "-p", work_dir,
                *[arg for platform in KICS_PLATFORMS for arg in ("-t", platform)],
                "-q", os.path.join(KICS_ASSETS_DIR, "queries"),
                "-b", os.path.join(KICS_ASSETS_DIR, "libraries"),
                "--disable-full-descriptions",
                "--no-progress",
                "--report-formats", "json",
                "-o", report_dir,
                "--output-name", "kics",
            ],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        report_path = os.path.join(report_dir, "kics.json")
        # KICS exits non-zero when it finds results, by severity -- that is
        # expected, not a failure, so the report's presence is the signal.
        if not os.path.exists(report_path):
            raise ScannerError(
                f"kics wrote no report (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
            )
        try:
            with open(report_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ScannerError(f"kics produced unparseable output: {exc}") from exc
    finally:
        shutil.rmtree(report_dir, ignore_errors=True)


def _kics_unparsed_count(report):
    """How many files KICS opened and could not read.

    KICS does not say *which*, and reports `files_failed_to_scan: 0` even when
    it has silently dropped a file -- measured 2026-09-23 on a deliberately
    broken template. The only honest signal it gives is the gap between
    `files_scanned` and `files_parsed`, and that is a count without names.

    So this is deliberately not wired into scan_errors, which is a list of
    files: the scanner's own template parse check (_json_template_verdict) and checkov's
    parsing_errors both name the file, and between them ARM and Bicep are
    covered. This exists so the gap is logged rather than invisible.
    """
    scanned = report.get("files_scanned") or 0
    parsed = report.get("files_parsed") or 0
    return max(scanned - parsed, 0)


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


# KICS's category -> finding_class. Everything else is a misconfiguration,
# which is what its queries overwhelmingly are.
KICS_CATEGORY_TO_FINDING_CLASS = {
    "Secret Management": "secret",
}


def _relativize_kics_path(file_path, work_dir):
    """Strip the scratch directory off a path KICS reported.

    KICS reports each file relative to its own working directory, which it
    inherits from this process -- so `/tmp/scan-abc/main.bicep` comes back as
    `../../tmp/scan-abc/main.bicep` from /var/task. Resolving it against the
    same cwd and then relativising against work_dir is exact rather than a
    prefix-strip, which is what the other two tools need.
    """
    try:
        rel = os.path.relpath(os.path.abspath(file_path), work_dir)
    except ValueError:
        # Different drives on Windows, which only happens in tests.
        return file_path.replace("\\", "/").lstrip("./")
    return rel.replace(os.sep, "/")


def _normalize_kics(report, work_dir, pr_id, classifications=None):
    """KICS's report -> findings.

    The rule id is the query's UUID rather than its name: the name is prose
    and has been reworded upstream before, where the id is what KICS treats
    as the rule's identity. corpus/rule_mappings.json is keyed on it, and the
    name rides along as the title so a reviewer and the remediation prompt
    still get something readable.
    """
    now = datetime.now(timezone.utc).isoformat()
    findings = []
    for query in report.get("queries") or []:
        finding_class = KICS_CATEGORY_TO_FINDING_CLASS.get(
            query.get("category"), "misconfiguration")
        for hit in query.get("files") or []:
            file_path = _relativize_kics_path(hit.get("file_name", ""), work_dir)
            line = hit.get("line")
            findings.append(_build_finding(
                pr_id=pr_id,
                source="kics",
                rule_id=query.get("query_id", "unknown"),
                file_path=file_path,
                line_range=[line, line],
                severity=(query.get("severity") or "UNKNOWN").upper(),
                target_type=_target_type_for(file_path, "", classifications),
                finding_class=finding_class,
                now=now,
                # KICS names the resource and its type separately; the pair is
                # what remediation-agent's supersede matches on.
                resource=hit.get("resource_name") or hit.get("search_key") or "",
                title=query.get("query_name") or "",
                description=query.get("description") or "",
            ))
    return findings


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


def _normalize_trivy(results, pr_id, classifications=None):
    now = datetime.now(timezone.utc).isoformat()
    findings = []
    for r in results:
        target_type = _target_type_for(r.get("Target", ""), r.get("Type"), classifications)
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
            target_type=target_type,
            finding_class=TRIVY_CLASS_TO_FINDING_CLASS.get(r.get("Class"), "misconfiguration"),
            now=now,
            resource=cause.get("Resource") or "",
            title=r.get("Title") or "",
            description=r.get("Description") or "",
        ))
    return findings


def _yaml_module():
    """PyYAML, from the same /opt/python the checkov subprocess reads.

    Not a new dependency: checkov ships PyYAML, and the image's strip removes
    only numpy and boto3 (see the Dockerfile). Imported lazily and only when
    there is a YAML file to check, so a Terraform-only scan never touches it.

    Raises rather than returning None when it is missing. A parse check that
    quietly does not run is precisely the fail-open this function exists to
    close, and ScannerError is this module's word for "a scan that did not
    happen" rather than "a scan that found nothing".
    """
    if LAYER_PYTHON_PATH not in sys.path:
        sys.path.append(LAYER_PYTHON_PATH)
    try:
        import yaml
    except ImportError as exc:
        raise ScannerError(
            "PyYAML is not importable, so the YAML files in this snapshot cannot be "
            "checked for parseability; refusing to report a scan whose parse check "
            "did not run"
        ) from exc
    return yaml


def _cfn_aware_loader(yaml_mod):
    """SafeLoader plus a constructor per CloudFormation intrinsic tag.

    The check this feeds asks one question -- can this file be read at all --
    so the constructors only have to consume the node, not model what the
    intrinsic means. Each returns the node's own value, dispatching on node
    type because the intrinsics take all three: `!Ref Foo` is a scalar,
    `!Join [",", [...]]` a sequence, and `!GetAtt` appears in both forms.

    Subclassed rather than registered on SafeLoader itself, which would be
    global and would leak these tags into checkov's own PyYAML use in the
    same interpreter -- except that checkov runs in a subprocess, so it would
    not, and the subclass is still right: a constructor added to a shared
    loader is exactly the kind of action at a distance that makes a later
    parse check pass for a reason nobody can find.
    """
    class Loader(yaml_mod.SafeLoader):
        pass

    def construct(loader, node):
        if isinstance(node, yaml_mod.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        if isinstance(node, yaml_mod.MappingNode):
            return loader.construct_mapping(node, deep=True)
        return loader.construct_scalar(node)

    for tag in CFN_INTRINSIC_TAGS:
        Loader.add_constructor(tag, construct)
    return Loader


def _unparseable_admitted_files(downloaded, work_dir):
    """Admitted files this scanner cannot parse itself, relative to work_dir.

    The tools are not enough. Measured 2026-09-22 against the pinned Trivy
    0.74.0 and checkov 3.3.16: a Kubernetes manifest that is not valid YAML
    is invisible to *both*. Trivy reports "Detected config files num=0" and
    logs nothing; checkov's kubernetes runner emits no report at all -- not
    even a parsing_errors entry, where its arm and bicep runners both do (a
    valid manifest in the same place gives 20 failed checks, so the runner
    itself runs). Zero findings with an empty scan_errors is exactly what
    remediation-agent's self-check reads as "the fix worked", so a fix that
    broke a manifest's YAML earned a scanner-verified badge. That is the
    fail-open multi-iac-spec §4 exists to prevent, and neither tool closes
    it.

    So the scanner parses what it admitted, itself. YAML here; ARM gets the
    same guarantee from _json_template_verdict, which has to parse the file to classify
    it at all. Bicep and Terraform are reported by the tools. A Go template is
    skipped because it is not a file this scanner failed to read -- it is one
    this scanner does not handle.

    The loader knows CloudFormation's short-form intrinsics (see
    CFN_INTRINSIC_TAGS). Without them a `!Sub` made an ordinary template
    unreadable to this check, which is the same mistake in the other
    direction: reporting a file the scanner can read as one it cannot.
    """
    yaml_paths = [p for p in downloaded if p.endswith((".yaml", ".yml"))]
    if not yaml_paths:
        return []

    yaml_mod = _yaml_module()
    loader = _cfn_aware_loader(yaml_mod)
    unparseable = []
    for path in yaml_paths:
        rel = os.path.relpath(path, work_dir).replace(os.sep, "/")
        try:
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            unparseable.append(rel)
            continue
        if GO_TEMPLATE_RE.search(content):
            continue
        try:
            for _ in yaml_mod.load_all(content, Loader=loader):
                pass
        except yaml_mod.YAMLError:
            unparseable.append(rel)
    return unparseable


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


def _normalize_checkov(report, pr_id, classifications=None):
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
                    file_path,
                    "" if check_type in CHECKOV_TYPE_TO_FINDING_CLASS else check_type,
                    classifications,
                ),
                finding_class=finding_class,
                now=now,
                resource=c.get("resource") or "",
                title=c.get("check_name") or "",
                # checkov carries no prose beyond the name; guideline is a URL.
                description="",
            ))
    return findings


def _build_finding(pr_id, source, rule_id, file_path, line_range, severity,
                   target_type, finding_class, now, resource="", title="", description=""):
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
        # What the rule means, in the scanner's own words. A Trivy id is a
        # number ("AWS-0091") and the model drafting a fix for it had only
        # that to go on: on terragoat's s3.tf (2026-09-21) it read AWS-0091
        # (ignore public ACLs) as versioning and AWS-0093 (restrict public
        # buckets) as encryption, and fixed those instead. Not in the id
        # hash: the text is the tool's, and a tool upgrade rewording a title
        # must not renumber the finding.
        "title": title,
        "description": description,
        # The resource address the rule fired on ("aws_s3_bucket.financials").
        # Not in the id hash either (see _write_findings); it is what lets
        # remediation-agent tell that a fix to one of five buckets in a file
        # resolved *this* finding rather than only that the rule fires once
        # less often.
        "resource": resource,
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

      scanner-owned   severity, title, description, resource, last_seen_at,
                      updated_at -- always refreshed, because the tool is the
                      authority on them
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
                "title = :title, description = :description, #resource = :resource, "
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
            ExpressionAttributeNames={
                "#source": "source", "#file": "file", "#status": "status",
                "#resource": "resource",
            },
            ExpressionAttributeValues={
                ":finding_id": finding["finding_id"],
                ":target_type": finding["target_type"],
                ":finding_class": finding["finding_class"],
                ":source": finding["source"],
                ":rule_id": finding["rule_id"],
                ":file": finding["file"],
                ":line_range": finding["line_range"],
                ":severity": finding["severity"],
                ":title": finding.get("title", ""),
                ":description": finding.get("description", ""),
                ":resource": finding.get("resource", ""),
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
