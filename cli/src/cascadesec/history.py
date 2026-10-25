"""The earlier version a change is judged against (docs/cli-spec.md §6, §7).

A finding blocks only if the change brought it: the scan of the files as
they are now has it, and a scan of the same files as they were before the
change does not. Matching is by fingerprint, which holds when lines move,
so an edit above a resource does not make its findings new. Comparing two
scans, rather than keeping the findings in the changed files, is what
catches a change in one file that makes another vulnerable -- a variable's
default turned off in variables.tf, opening the bucket in main.tf -- and
what lets an edit to a file with old findings through.

The earlier version comes from git, never from the working tree:

  a push                     the merge base of what the remote has and what
                             is pushed, the range pre-commit took the files from
  a commit                   HEAD
  scan --changed-only REV    REV

Only the files the scanner reads are written out, into a temporary
directory, and that directory is scanned exactly as the current files are.
"""

import os
import shutil
import subprocess
import tempfile
from collections import namedtuple
from pathlib import PurePosixPath

# What the scanner reads: iac-scanner's SNAPSHOT_SUFFIXES, plus the .json
# and .template files it sniffs. tests/test_history.py holds this to its list.
ADMITTED = (".tf", ".tf.json", ".tfvars", ".tfvars.json", ".tofu", ".tofu.json", ".yaml", ".yml",
            ".bicep", ".json", ".template")
REGULAR = ("100644", "100755")      # not symlinks (120000) or submodules (160000)

# rev: the commit scanned as "before". label: how the output names it.
# files: the files the change's own version holds in the scanned
# directories (what is pushed, or what is staged), so a finding in an
# untracked file beside a changed one is left out rather than called new.
Earlier = namedtuple("Earlier", "rev label files")


class Unavailable(Exception):
    """git could not answer: not a repository, a bad revision, no git, or,
    inside the scanner image, a checkout whose .git points outside the mount
    (a worktree or a submodule)."""


def git(base, *args, run=None, binary=False, stdin=None):
    run = run or subprocess.run
    kwargs = {"capture_output": True, "input": stdin}
    if not binary:
        kwargs.update(text=True, encoding="utf-8", errors="replace")
    try:
        done = run(["git", "--literal-pathspecs", "-C", str(base), *args], **kwargs)
    except FileNotFoundError:
        raise Unavailable("git is not on PATH") from None
    if done.returncode != 0:
        err = done.stderr.decode("utf-8", "replace") if binary else (done.stderr or "")
        lines = err.strip().splitlines()
        raise Unavailable(lines[-1] if lines else f"git {args[0]} exited {done.returncode}")
    return done.stdout


def commit(base, rev, run=None):
    """The full sha `rev` names, or None when there is none (HEAD before the
    first commit)."""
    try:
        return git(base, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}", run=run).strip() or None
    except Unavailable:
        return None


def merge_base(base, a, b, run=None):
    """Where b leaves a. Histories with nothing in common fall back to a, as
    pre-commit's own a...b does."""
    try:
        return git(base, "merge-base", a, b, run=run).strip() or a
    except Unavailable:
        return a


def _safe(path):
    """A path git listed that is safe to write under a temporary directory.
    Git refuses `..` and `.git` on checkout, but a tree fetched without fsck
    can still hold them."""
    parts = path.split("/")
    return not any(p in ("", ".", "..") or p.lower() == ".git" or "\\" in p or ":" in p for p in parts)


def files_in(base, rev, dirs=None, run=None):
    """{path: blob sha} for the regular files the scanner reads, in commit
    `rev` (or the index, when rev is None), POSIX and relative to `base`.
    With `dirs`, only files directly in those directories ("." the top),
    which is the hook's scope; without, everything under `base`."""
    specs = list(dirs) if dirs else ["."]
    if rev is None:
        out = git(base, "ls-files", "--stage", "-z", "--", *specs, run=run)
    else:
        out = git(base, "ls-tree", "-r", "-z", rev, "--", *specs, run=run)
    entries = {}
    for record in out.split("\0"):
        if not record:
            continue
        meta, path = record.split("\t", 1)
        # ls-files: "mode sha stage"; ls-tree: "mode type sha".
        fields = meta.split()
        mode, sha = fields[0], (fields[1] if rev is None else fields[2])
        if mode not in REGULAR or not path.endswith(ADMITTED) or not _safe(path):
            continue
        if dirs is not None and str(PurePosixPath(path).parent) not in dirs:
            continue
        entries[path] = sha
    return entries


def _blobs(out):
    """{sha: bytes} from `git cat-file --batch` output."""
    blobs, i = {}, 0
    while i < len(out):
        end = out.index(b"\n", i)
        header = out[i:end].decode("ascii", "replace").split()
        if len(header) != 3:
            raise Unavailable(f"git cat-file: {' '.join(header)}")
        sha, _, size = header
        start = end + 1
        blobs[sha] = out[start:start + int(size)]
        i = start + int(size) + 1
    return blobs


def export(base, rev, dest, dirs=None, run=None):
    """Write the files files_in lists for `rev` under `dest`, at the same
    relative paths, so a scan of `dest` names them as a scan of `base` does."""
    entries = files_in(base, rev, dirs, run=run)
    if entries:
        wanted = "".join(f"{sha}\n" for sha in sorted(set(entries.values())))
        blobs = _blobs(git(base, "cat-file", "--batch", run=run, binary=True, stdin=wanted.encode()))
        for path, sha in entries.items():
            target = os.path.join(dest, *path.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(blobs[sha])
    return set(entries)


def scan_at(base, rev, scan, dirs=None, run=None):
    """The findings `scan(directory)` gives for `rev`'s files, scanned in a
    temporary directory removed afterwards."""
    dest = tempfile.mkdtemp(prefix="cascadesec-earlier-")
    try:
        export(base, rev, dest, dirs, run=run)
        return scan(dest).get("findings") or []
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def for_hook(root, files, dirs, env, run=None):
    """(Earlier, None), or (None, why there is nothing to compare with).

    A push has its range from pre-commit (PRE_COMMIT_FROM_REF and _TO_REF).
    With none, the hook is either checking a commit -- every file it was
    given is staged -- or checking files on request (`pre-commit run
    --all-files`, `--files`, or the first push of a new history), and then
    there is no change to compare, only files to judge."""
    from_ref, to_ref = env.get("PRE_COMMIT_FROM_REF"), env.get("PRE_COMMIT_TO_REF")
    try:
        if from_ref and to_ref:
            rev = merge_base(root, from_ref, to_ref, run=run)
            return Earlier(rev, f"{rev[:12]}, where this push leaves what the remote has",
                           set(files_in(root, to_ref, dirs, run=run))), None
        head = commit(root, "HEAD", run=run)
        if head is None:
            git(root, "rev-parse", "--git-dir", run=run)        # Unavailable if not a repository
            return None, "this is the first commit, so there is no earlier version"
        staged = set(git(root, "diff", "--cached", "--name-only", "--no-renames", "-z", "HEAD",
                         run=run).split("\0")) - {""}
        if not set(files) <= staged:
            return None, ("the files pre-commit passed are not a staged change (`pre-commit run "
                          "--all-files` or `--files`, or the first push of a new history)")
        return Earlier(head, f"{head[:12]}, the last commit", set(files_in(root, None, dirs, run=run))), None
    except Unavailable as e:
        if os.path.isfile(os.path.join(root, ".git")):
            # Measured in the docker hook: a worktree's .git names a gitdir
            # on the host, which the container's mount does not include.
            return None, ("this checkout's .git points outside the container (a worktree or a "
                          "submodule), so its history cannot be read here; the `cascadesec` hook, "
                          "which runs on the host, can compare")
        return None, f"git could not read this repository's history here: {e}"
