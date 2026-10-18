#!/usr/bin/env python3
"""Local mode's entry point inside the scanner image (docs/cli-spec.md §3.1-3.2).

  docker run --rm --network none --read-only --tmpfs /tmp \\
    -v "<absolute path>:/src:ro" \\
    --entrypoint python <scanner image> /var/task/local_main.py /src

Copies the files a snapshot would hold from /src into /tmp/scan-<id>, scans
them with handler.scan_directory -- the code path the Lambda runs -- and
prints one JSON document on stdout. Nothing is persisted and nothing leaves
the container; --network none enforces that rather than trusting it.

Why copy rather than scan /src in place: the tools walk the directory they
are given, so in place they would also see node_modules, .terraform,
cdk.out and every other file the Lambda never receives. Local and pipeline
results for the same repository can only agree if their inputs do, so the
copy applies the same two rules the uploaders do -- SKIP_DIRS, and
handler._is_candidate then handler._admit for each file.

Apps that must run before they can be scanned -- CDK, Pulumi, Helm -- are
listed, not scanned (§3.5 stage 1). Their IaC exists only as the output of
running them, and this image runs nothing. A Helm chart's templates are Go
templates the scanner deliberately skips, so without the list a chart-only
repository would come back clean when it was never looked at.

Output, one JSON object:
  findings          what the scan found, without the pipeline's record fields
  scan_errors       admitted files a tool could not parse
  unscanned_apps    [{path, kind, reason}] app roots this run could not scan
  scanned_files     how many files were admitted and scanned
The exit status is 0 whenever the scan ran; what the result means -- clean,
findings, incomplete -- is the CLI's to decide (§5). 2 is a usage error.
"""

import argparse
import contextlib
import json
import os
import shutil
import sys
import uuid

import handler

# Must match scripts/scan.py's, run_external.py's and github-gateway's;
# corpus/test_corpus.py asserts every copy agrees. cdk.out is in it because
# a synthesized template scanned as if someone wrote it is a scope error
# (multi-iac-spec §7.1): locally it is reported as an app instead.
SKIP_DIRS = {".terraform", ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             "cdk.out"}

# A file that marks a directory as an app root, and what it is.
APP_MARKERS = {"cdk.json": "cdk", "Pulumi.yaml": "pulumi", "Pulumi.yml": "pulumi", "Chart.yaml": "helm"}
APP_REASONS = {
    "cdk": "a CDK app: its CloudFormation exists only after `cdk synth`, which local mode does not run",
    "pulumi": "a Pulumi program: its resources exist only after it runs, which local mode does not do",
    "helm": "a Helm chart: its templates are scanned only once rendered, which local mode does not do",
}

# What a local finding carries. The pipeline's record fields -- pk, sk,
# status, control_mappings, proposed_fix, timestamps -- describe a stored
# review item, and none of them is true of a scan that stored nothing.
FINDING_FIELDS = ("finding_id", "fingerprint", "source", "rule_id", "title", "description",
                  "severity", "file", "line_range", "resource", "target_type", "finding_class",
                  "origin")


def walk(src):
    """(rel_path, abs_path) for each regular file under `src`, outside
    SKIP_DIRS, in a stable order. Symlinks are not followed or copied: a
    link can point outside the mounted tree, and the gateway refuses them
    for the same reason."""
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            yield os.path.relpath(path, src).replace(os.sep, "/"), path


def copy_snapshot(src, work_dir):
    """(handler.Snapshot, unscanned_apps): the admitted files copied into
    `work_dir`, and the app roots found on the way."""
    snapshot, apps = handler.Snapshot(), []
    for rel, path in walk(src):
        name = rel.rsplit("/", 1)[-1]
        if name in APP_MARKERS:
            kind = APP_MARKERS[name]
            root = rel.rsplit("/", 1)[0] if "/" in rel else "."
            apps.append({"path": root, "kind": kind, "reason": APP_REASONS[kind]})
        if not handler._is_candidate(rel):
            continue
        dest = os.path.join(work_dir, *rel.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(path, dest)
        snapshot.add(rel, dest)
    return snapshot, apps


def scan(src, pr_id="local"):
    work_dir = os.path.join("/tmp" if os.path.isdir("/tmp") else os.getcwd(), f"scan-{uuid.uuid4().hex}")
    os.makedirs(work_dir)
    try:
        snapshot, apps = copy_snapshot(src, work_dir)
        findings, scan_errors = [], sorted(snapshot.unreadable_templates)
        if snapshot.downloaded:
            # No source maps: local mode synthesizes nothing (§3.5 stage 1),
            # so no CDK template reaches here -- SKIP_DIRS drops cdk.out.
            findings, scan_errors = handler.scan_directory(
                work_dir, pr_id, snapshot.downloaded, snapshot.unreadable_templates,
                snapshot.classifications, cdk_source_maps={})
        return {
            "scanned_files": len(snapshot.downloaded),
            "findings": [{k: f[k] for k in FINDING_FIELDS if k in f} for f in findings],
            "scan_errors": scan_errors,
            "unscanned_apps": apps,
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main(argv=None, stdout=None):
    stdout = stdout or sys.stdout
    ap = argparse.ArgumentParser(description="Scan a directory with the pipeline's scanner, locally.")
    ap.add_argument("src", nargs="?", default="/src", help="the directory to scan (default /src)")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.src):
        print(f"local_main: {args.src} is not a directory", file=sys.stderr)
        return 2
    # stdout carries exactly one JSON document. Anything the scan prints --
    # a tool's chatter, a stray print -- goes to stderr with the logs.
    with contextlib.redirect_stdout(sys.stderr):
        result = scan(args.src)
    stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
