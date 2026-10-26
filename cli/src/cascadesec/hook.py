"""`cascadesec hook FILE...`: the pre-commit hook (docs/cli-spec.md §7).

pre-commit passes the files a commit or push changes. The hook scans each
directory holding one -- the directory rather than the file, because a
Terraform module and its tfvars resolve across it -- and reports only
findings in the files themselves, after the baseline. A finding in a file
nobody touched was there before, and blocking a commit over it is how a
hook gets uninstalled.

The scoping is S5's: scope_to_changes and the baseline are the same calls
`cascadesec scan --changed-only` makes, so the hook and the CLI cannot
decide differently about one file. It runs the same pinned image, under
--network none, through scan.run_scanner.

Two hooks run it (.pre-commit-hooks.yaml). `cascadesec` is the installed
CLI, which starts the scanner image. `cascadesec-docker` is pre-commit
starting the hook image (cli/Dockerfile: the scanner image with this CLI on
top), which runs this same command: there it cannot start a container, so it
calls local_main's scan in-process instead (CASCADESEC_IN_IMAGE, set by that
Dockerfile). Everything after the scan -- scoping, baseline, verdict -- is
one code path for both.

It ships as `stages: [pre-push]` by default (decision D6): a cold local
scan takes 10-20 seconds, and 81 on module-heavy Terraform (§3.4), which a
commit-time hook would make every commit pay.
"""

import contextlib
import os
import sys
from pathlib import PurePosixPath

from cascadesec import baseline
from cascadesec import scan as scanning
from cascadesec.errors import USAGE, CliError


def staged_paths(files, root):
    """The files pre-commit passed, as POSIX paths relative to the repo root.
    pre-commit runs hooks from the root and passes root-relative names, but
    accept absolute ones and Windows separators as well."""
    rels = set()
    root = os.path.abspath(root)
    for f in files:
        path = os.path.abspath(os.path.join(root, f))
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        if rel.startswith("../"):
            raise CliError(f"{f} is outside the repository at {root}", USAGE)
        rels.add(rel)
    return rels


def directories(paths):
    return sorted({str(PurePosixPath(p).parent) if "/" in p else "." for p in paths})


def docker_command(root, image_ref, dirs):
    command = scanning.docker_command(root, image_ref)
    for d in dirs:
        command += ["--only-dir", d]
    return command


def scan_in_image(root, dirs):
    """The scan, in this process, when this process is already the scanner
    image. local_main lives in the Lambda task root, beside handler.py."""
    task_root = os.environ.get("LAMBDA_TASK_ROOT", "/var/task")
    if task_root not in sys.path:
        sys.path.insert(0, task_root)
    import local_main  # noqa: PLC0415 -- only importable inside the image

    corpus = local_main.load_corpus()
    # stdout carries the hook's table; the tools' chatter goes to stderr.
    with contextlib.redirect_stdout(sys.stderr):
        return local_main.scan(root, corpus=corpus, only_dirs=set(dirs))


def run(files, root, image_ref, fail_on, allow_scan_errors, baseline_path, skips=(), run=None,
        which=None, in_image=False):
    """The summary `scan` would print for these files, with its exit code."""
    staged = staged_paths(files, root)
    if not staged:
        return None
    dirs = directories(staged)
    document = baseline.load(baseline_path) if baseline_path else None
    if in_image:
        result = scan_in_image(root, dirs)
    else:
        result = scanning.run_scanner(
            root, image_ref, run=run, which=which,
            command=docker_command(os.path.abspath(root), image_ref, dirs))
    full = result.get("findings") or []
    result, skipped = baseline.skip_apps(result, root, list(skips))
    scoped, outside = baseline.scope_to_changes(result, staged)
    kept, suppressed, _ = baseline.apply(scoped.get("findings") or [], document)
    scoped = {**scoped, "findings": kept}
    summary = scanning.summarise(scoped, root, image_ref, fail_on, allow_scan_errors)
    return {
        **summary,
        "hook_files": sorted(staged),
        "hook_dirs": dirs,
        "baseline": str(baseline_path) if document is not None else None,
        "baselined_count": len(suppressed),
        "baseline_fixed": [],          # a hook sees part of the repo; fixed is a full scan's call
        "changed_only": None,          # said as "only the changed files" instead
        "outside_changes_count": outside,
        "skipped_apps": [{k: a[k] for k in ("path", "kind", "reason", "source")} for a in skipped],
        "_scanned_findings": len(full),
    }
