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

Each finding also says what a remote scan would make of it (§3.3), read
from the control corpus the image ships at /opt/corpus:
  candidates        the controls mapping-agent would choose among -- not its
                    choice, which takes the model and a remote scan
  raw_reason        when there is no candidate: why the pipeline leaves it
                    raw (no-control, hygiene, not-fixable, unreviewed)
  detection_only    true for CDK and Pulumi: mapped remotely, never fixed

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
import glob
import json
import os
import shutil
import sys
import uuid

import handler

CORPUS_DIR = os.environ.get("CASCADESEC_CORPUS_DIR", "/opt/corpus")

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


# ---------- what a remote scan would make of each finding ----------
#
# Copies of mapping-agent's, held to it by corpus/test_corpus.py until the
# core is one shared package (portable-runtime-spec §8). Local output
# predicts what the pipeline will do, so it must decide it the same way.

UNREVIEWED = "unreviewed"
DETECTION_ONLY_TARGET_TYPES = {"cdk", "pulumi"}


def _candidates_for(rule_mappings, finding):
    """The candidate controls that apply to this finding: mapping-agent's
    rule, including a candidate's optional target_type scope."""
    refs = rule_mappings.get(f"{finding['source']}:{finding['rule_id']}") or []
    target_type = finding.get("target_type")
    # A synthesized CDK template is CloudFormation, and a control scoped to
    # CloudFormation fits it as well as it fits a hand-written template.
    matches = {target_type} | ({"cloudformation"} if target_type == "cdk" else set())
    return [r for r in refs
            if "target_type" not in r or r["target_type"] in matches]


def _unmapped_reason(unmapped_rules, finding):
    """Why this finding has no candidate, as mapping-agent records it."""
    entry = unmapped_rules.get(f"{finding['source']}:{finding['rule_id']}")
    return entry["reason"] if entry else UNREVIEWED


def load_corpus(corpus_dir=None):
    """(mappings, unmapped, {(framework, control_id): title}). The image
    always carries the corpus; one without it was built wrong, and a run
    that silently reported no candidates would look like a corpus with no
    mappings."""
    corpus_dir = corpus_dir or CORPUS_DIR
    path = os.path.join(corpus_dir, "rule_mappings.json")
    try:
        with open(path, encoding="utf-8") as fh:
            corpus = json.load(fh)
    except (OSError, ValueError) as e:
        raise SystemExit(f"local_main: no control corpus at {path} ({e}); the image was built "
                         "without `--build-context corpus=...`")
    titles = {}
    for framework_file in sorted(glob.glob(os.path.join(corpus_dir, "frameworks", "*.json"))):
        with open(framework_file, encoding="utf-8") as fh:
            framework = json.load(fh)
        for control in framework.get("controls", []):
            titles[(framework["framework"], control["control_id"])] = control.get("title")
    return corpus["mappings"], corpus.get("unmapped", {}), titles


def annotate(finding, corpus):
    mappings, unmapped, titles = corpus
    candidates = _candidates_for(mappings, finding)
    finding["candidates"] = [
        {"framework": c["framework"], "control_id": c["control_id"],
         "title": titles.get((c["framework"], c["control_id"]))} for c in candidates]
    if not candidates:
        finding["raw_reason"] = _unmapped_reason(unmapped, finding)
    if finding.get("target_type") in DETECTION_ONLY_TARGET_TYPES:
        finding["detection_only"] = True
    return finding


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


def copy_snapshot(src, work_dir, only_dirs=None):
    """(handler.Snapshot, unscanned_apps): the admitted files copied into
    `work_dir`, and the app roots found on the way.

    `only_dirs`, when given, limits the copy to files directly in those
    directories (POSIX, relative to `src`, "." for the root): the pre-commit
    hook's scope (cli-spec §7). A whole directory rather than the changed
    files alone, because a Terraform module and its tfvars resolve across
    one. App roots are still looked for everywhere; the CLI keeps the ones a
    changed file is inside."""
    snapshot, apps = handler.Snapshot(), []
    for rel, path in walk(src):
        name = rel.rsplit("/", 1)[-1]
        if name in APP_MARKERS:
            kind = APP_MARKERS[name]
            root = rel.rsplit("/", 1)[0] if "/" in rel else "."
            apps.append({"path": root, "kind": kind, "reason": APP_REASONS[kind]})
        if not handler._is_candidate(rel):
            continue
        if only_dirs is not None and (rel.rsplit("/", 1)[0] if "/" in rel else ".") not in only_dirs:
            continue
        dest = os.path.join(work_dir, *rel.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(path, dest)
        snapshot.add(rel, dest)
    return snapshot, apps


def scan(src, pr_id="local", corpus=None, only_dirs=None):
    work_dir = os.path.join("/tmp" if os.path.isdir("/tmp") else os.getcwd(), f"scan-{uuid.uuid4().hex}")
    os.makedirs(work_dir)
    try:
        snapshot, apps = copy_snapshot(src, work_dir, only_dirs)
        findings, scan_errors = [], sorted(snapshot.unreadable_templates)
        if snapshot.downloaded:
            # No source maps: local mode synthesizes nothing (§3.5 stage 1),
            # so no CDK template reaches here -- SKIP_DIRS drops cdk.out.
            findings, scan_errors = handler.scan_directory(
                work_dir, pr_id, snapshot.downloaded, snapshot.unreadable_templates,
                snapshot.classifications, cdk_source_maps={})
        corpus = corpus or load_corpus()
        return {
            "scanned_files": len(snapshot.downloaded),
            "findings": [annotate({k: f[k] for k in FINDING_FIELDS if k in f}, corpus)
                         for f in findings],
            "scan_errors": scan_errors,
            "unscanned_apps": apps,
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main(argv=None, stdout=None):
    stdout = stdout or sys.stdout
    ap = argparse.ArgumentParser(description="Scan a directory with the pipeline's scanner, locally.")
    ap.add_argument("src", nargs="?", default="/src", help="the directory to scan (default /src)")
    ap.add_argument("--only-dir", action="append", metavar="DIR",
                    help="scan only files directly in DIR, relative to src; repeat for several "
                         "(the pre-commit hook's scope)")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.src):
        print(f"local_main: {args.src} is not a directory", file=sys.stderr)
        return 2
    # stdout carries exactly one JSON document. Anything the scan prints --
    # a tool's chatter, a stray print -- goes to stderr with the logs.
    corpus = load_corpus()          # before scanning: a misbuilt image fails fast
    with contextlib.redirect_stdout(sys.stderr):
        only = {d.replace("\\", "/").strip("/") or "." for d in args.only_dir} if args.only_dir else None
        result = scan(args.src, corpus=corpus, only_dirs=only)
    stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
