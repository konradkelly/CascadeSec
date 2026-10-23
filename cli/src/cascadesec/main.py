"""`cascadesec`: the command line (docs/cli-spec.md §2).

Built so far: track R (§13) -- the skeleton, signing a person in, reading a
PR's findings (`findings`, `show`), deciding on a fix (`approve`, `reject`,
`edit`), and committing the approved ones (`commit`) -- and from track S,
`scan` in local mode with its baseline (`baseline`), and the pre-commit
`hook`. Commands that don't exist yet aren't registered, so
`--help` lists only what works.

Results go to stdout in --format; progress, prompts and errors go to stderr,
so `--format json` output can be piped whatever else is printed.
"""

import argparse
import difflib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

from cascadesec import __version__, api, auth, baseline, config, editor, hook, prs, render, review
from cascadesec import commit as committing
from cascadesec import scan as scanning
from cascadesec.errors import OK, REFUSED, USAGE, CliError
from cascadesec.store import SessionStore

FULL_FINDING_ID = re.compile(r"^[0-9a-f]{16}$")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cascadesec",
        description="CascadeSec from the terminal.",
    )
    parser.add_argument(
        "--format", choices=("table", "json"),
        help="output format (default: table on a terminal, json otherwise)",
    )
    commands = parser.add_subparsers(dest="command", metavar="<command>", required=True)

    login = commands.add_parser("login", help="sign in through the browser")
    login.add_argument(
        "--no-browser", action="store_true",
        help="print the sign-in URL and paste back the redirect, for a machine with no browser (SSH)",
    )
    commands.add_parser("logout", help="revoke the session and remove it from the keyring")
    commands.add_parser("whoami", help="who is signed in, their groups, and when the token expires")
    commands.add_parser("version", help="the CLI's version and the scanner image it runs")

    scan = commands.add_parser(
        "scan", help="scan a directory locally: findings and candidate controls, offline",
        description="Scan a directory with the pipeline's scanner, run on this machine in Docker "
                    "with no network: the same tools and versions, so the same findings a remote "
                    "scan gets. Each finding lists the controls a remote scan would choose among, "
                    "or why it would stay raw. No account and no model are involved, so there is "
                    "no citation and no fix. Exit 0 clean, 1 findings at or above --fail-on, "
                    "3 incomplete (a file did not parse, or an app was not run).")
    scan.add_argument("path", nargs="?", default=".", help="the directory to scan (default: here)")
    scan.add_argument("--fail-on", choices=scanning.FAIL_ON, default="high",
                      help="exit 1 when a finding is at or above this severity (default high); "
                           "`any` includes findings with no severity, which is all of checkov's")
    scan.add_argument("--allow-scan-errors", action="store_true",
                      help="report the findings' result even when the scan was incomplete")
    scan.add_argument("--image", help="the scanner image (default: $CASCADESEC_SCANNER_IMAGE, "
                                      "then the image this CLI pins)")
    scan.add_argument("--output", metavar="FILE",
                      help="also write the result to FILE in --format (json if not given)")
    scan.add_argument("--baseline", metavar="FILE",
                      help=f"findings to leave out of the verdict (default: PATH/{baseline.FILE} if present)")
    scan.add_argument("--no-baseline", action="store_true", help="ignore the baseline file")
    scan.add_argument("--changed-only", metavar="REV",
                      help="report only what is in files changed since REV (git diff --name-only REV, "
                           "plus new untracked files)")

    base = commands.add_parser(
        "baseline", help=f"write {baseline.FILE}: the findings to accept for now",
        description=f"Scan PATH and write {baseline.FILE}, which `scan` then leaves out of its "
                    "verdict. Commit it: adding to it is a decision reviewed in a diff. --prune "
                    "removes entries that no longer fire, and adds nothing.")
    base.add_argument("path", nargs="?", default=".", help="the directory to scan (default: here)")
    base.add_argument("--prune", action="store_true",
                      help="only remove entries that no longer fire; add nothing new")
    base.add_argument("--file", metavar="FILE", help=f"where to write it (default: PATH/{baseline.FILE})")
    base.add_argument("--image", help="the scanner image (as for scan)")

    hk = commands.add_parser(
        "hook", help="the pre-commit hook: scan the given files' directories, report only them",
        description="Run by pre-commit (see .pre-commit-hooks.yaml), from the repository root, "
                    "with the files a commit or push changes. Scans each directory holding one and "
                    "reports only findings in those files, after the baseline. Exit codes as for scan.")
    hk.add_argument("files", nargs="*", help="the changed files, relative to the repository root")
    hk.add_argument("--fail-on", choices=scanning.FAIL_ON, default="high",
                    help="block when a finding is at or above this severity (default high)")
    hk.add_argument("--allow-scan-errors", action="store_true",
                    help="do not block on a changed file that failed to parse")
    hk.add_argument("--baseline", metavar="FILE",
                    help=f"findings to leave out (default: ./{baseline.FILE} if present)")
    hk.add_argument("--image", help="the scanner image (as for scan)")

    pr_help = "the PR: owner/repo#123, its GitHub URL, or a review-api id such as gh-1352957770-50"
    findings = commands.add_parser(
        "findings", help="a PR's findings, grouped as the dashboard groups them",
        description="List a PR's findings. Findings with a control come first, by what is left "
                    "to decide; raw ones follow, one row per rule, grouped by why they are raw.")
    findings.add_argument("pr", help=pr_help)
    findings.add_argument("--status", action="append", choices=review.STATUSES, metavar="STATUS",
                          help="only this status; repeat for several (" + ", ".join(review.STATUSES) + ")")
    findings.add_argument("--severity", choices=review.SEVERITIES, type=str.lower,
                          help="only findings at or above this severity")
    findings.add_argument("--file", help="only this file, directory, or glob (e.g. 'k8s/*.yaml')")

    show = commands.add_parser(
        "show", help="one finding: its controls, the fix, the self-check, and the audit trail")
    show.add_argument("pr", help=pr_help)
    show.add_argument("finding_id", help="the finding's id, or enough of its start to be unique")
    show.add_argument("--agent-diff", action="store_true",
                      help="show the agent's original diff where a reviewer has edited the fix")

    id_help = "the finding's id, or enough of its start to be unique"
    notes_help = "why, recorded in the audit trail"
    approve = commands.add_parser(
        "approve", help="accept a fix as drafted",
        description="Accept a fix as drafted. review-api refuses it while a fix it was drafted on "
                    "is not accepted, and says which.")
    reject = commands.add_parser(
        "reject", help="refuse a fix; never blocked",
        description="Refuse a fix. Never blocked, so it is always the way out of a chain gone "
                    "wrong. Fixes drafted on this one are reopened, and listed.")
    for p in (approve, reject):
        p.add_argument("pr", help=pr_help)
        p.add_argument("finding_id", help=id_help)
        p.add_argument("--notes", default="", help=notes_help)

    edit = commands.add_parser(
        "edit", help="correct a fix's file in your editor, then record it as edited",
        description="Open the fix's corrected file in $VISUAL or $EDITOR (Notepad on Windows if "
                    "neither is set; a GUI editor needs its wait flag, e.g. `code --wait`). On "
                    "save, show what changed and confirm, then send the whole file. The edit "
                    "has not been through the scanner, so its self-check reads as not passed.")
    edit.add_argument("pr", help=pr_help)
    edit.add_argument("finding_id", help=id_help)
    edit.add_argument("--notes", default="", help=notes_help)
    edit.add_argument("--file", metavar="PATH",
                      help="send this prepared file instead of opening an editor")
    edit.add_argument("--yes", action="store_true",
                      help="record without asking; required when there is no terminal")

    commit = commands.add_parser(
        "commit", help="commit a PR's approved fixes to its branch (committers only)",
        description="Show the commit plan -- per file, the diff from the branch to the approved "
                    "fixes, and what is held and why -- then confirm and commit it as the "
                    "CascadeSec Fixes app. What is confirmed is exactly what was printed: if the "
                    "plan moves before the request lands, nothing is committed.")
    commit.add_argument("pr", help=pr_help)
    commit.add_argument("--yes", action="store_true", help="commit without asking")
    commit.add_argument("--expect-sha", action="append", metavar="FILE=SHA",
                        help="the content hash the plan prints for a file; without a terminal, "
                             "--yes needs one for every file the plan commits")
    commit.add_argument("--no-wait", action="store_true",
                        help="return once the request is recorded, without waiting for the commit")
    commit.add_argument("--timeout", type=int, default=committing.DEFAULT_TIMEOUT, metavar="SECONDS",
                        help=f"how long to wait for the commit (default {committing.DEFAULT_TIMEOUT})")
    return parser


def main(argv=None, *, stdout=None, env=None, cwd=None, backend=None,
         prompt=None, interactive=None, run=None, sleep=None, clock=None):
    if stdout is None:
        stdout = sys.stdout
        # A finding's title or a fix's rationale may hold characters the
        # console's code page lacks; print them as `?` rather than crash.
        if hasattr(stdout, "reconfigure"):
            stdout.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    # pre-commit captures a hook's output, so it is never a terminal -- and
    # what it shows when a push is blocked is read by a person, not parsed.
    fmt = args.format or ("table" if stdout.isatty() or args.command == "hook" else "json")
    ctx = _Context(env, cwd, backend, prompt=prompt, interactive=interactive, run=run,
                   sleep=sleep, clock=clock)
    try:
        result = COMMANDS[args.command](args, ctx)
    except CliError as e:
        print(f"cascadesec: {e}", file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        print("cascadesec: interrupted", file=sys.stderr)
        return USAGE
    if fmt == "table" and args.command in RENDERERS:
        color = stdout.isatty() and "NO_COLOR" not in ctx.env
        RENDERERS[args.command](result, render.Out(stdout, color=color))
    else:
        _emit(result, fmt, stdout)
    # A command can finish with something to print and still not be done:
    # a commit request the committer held is exit 1 with its reasons shown.
    return result.get("_exit", OK)


class _Context:
    """Settings and the session store, loaded on first use: `version` needs
    neither, and shouldn't fail on a broken config file."""

    def __init__(self, env, cwd, backend, prompt=None, interactive=None, run=None,
                 sleep=None, clock=None):
        self._env, self._cwd, self._backend = env, cwd, backend
        self._settings = None
        # Questions go to stderr like every other prompt, so a confirmation
        # never lands in --format json output.
        self.prompt = prompt or _ask
        self.interactive = sys.stdin.isatty() if interactive is None else interactive
        self.run = run or subprocess.run
        self.sleep = sleep or time.sleep
        self.clock = clock or time.monotonic

    def stderr(self):
        return render.Out(sys.stderr, color=sys.stderr.isatty() and "NO_COLOR" not in self.env)

    @property
    def env(self):
        return os.environ if self._env is None else self._env

    @property
    def settings(self):
        if self._settings is None:
            self._settings = config.load(cwd=self._cwd, env=self._env)
        return self._settings

    def store(self):
        s = self.settings.require("auth_domain", "client_id")
        kwargs = {"backend": self._backend} if self._backend else {}
        return SessionStore(s.auth_domain, s.client_id, **kwargs)

    def client(self):
        return api.Client(self.settings, self.store())


# ---------- commands ----------

def cmd_login(args, ctx):
    claims = auth.login(ctx.settings, ctx.store(), open_browser=not args.no_browser)
    return {"signed_in_as": claims.get("email"), "groups": claims.get("cognito:groups", []),
            "deployment": ctx.settings.auth_domain}


def cmd_logout(args, ctx):
    had, revoked = auth.logout(ctx.settings, ctx.store())
    if had and not revoked:
        print("cascadesec: removed the local session, but Cognito did not confirm revoking it; "
              "it ends on its own when the refresh token expires", file=sys.stderr)
    return {"signed_out": had, "revoked": revoked}


def cmd_whoami(args, ctx):
    session = auth.current_session(ctx.settings, ctx.store())
    claims = auth.claims(session["id_token"])
    return {
        "email": claims.get("email"),
        "groups": claims.get("cognito:groups", []),
        # Group membership is as of when Cognito issued this token; someone
        # just added to `committers` signs in again (cognito.tf).
        "token_issued_at": _iso(claims.get("iat")),
        "token_expires_at": _iso(session.get("expires_at")),
        "signed_in_at": _iso(session.get("signed_in_at")),
        "deployment": ctx.settings.auth_domain,
    }


def cmd_version(args, ctx):
    return {"cli": __version__, "scanner_image": scanning.image(None, ctx.env)}


def cmd_scan(args, ctx):
    image_ref = scanning.image(args.image, ctx.env)
    if not os.path.isdir(args.path):
        raise CliError(f"{args.path} is not a directory", USAGE)
    print(f"cascadesec: scanning {os.path.abspath(args.path)} in {image_ref} (no network)",
          file=sys.stderr)
    # Before the scan, so a mistake in .cascadesec.toml or the baseline
    # costs a moment rather than a whole scan.
    settings = config.load(cwd=args.path, env=ctx.env)
    path = None if args.no_baseline else (args.baseline or baseline.default_path(args.path))
    document = baseline.load(path) if path else None
    if args.baseline and document is None:
        raise CliError(f"--baseline {args.baseline}: no such file", USAGE)
    result = scanning.run_scanner(args.path, image_ref, run=ctx.run)
    result, held_back = _hold_back(args, ctx, result, image_ref, settings, path, document)
    summary = {**scanning.summarise(result, args.path, image_ref, args.fail_on, args.allow_scan_errors),
               **held_back}
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            if (args.format or "json") == "json":
                fh.write(json.dumps(summary, indent=2) + "\n")
            else:
                render.scan_result(summary, render.Out(fh))
    return {**summary, "_exit": summary["exit_code"]}


def cmd_findings(args, ctx):
    pr_id = prs.resolve(args.pr, ctx.env)
    listing = ctx.client().get("prs", pr_id, "findings")
    everything = listing.get("findings") or []
    if not everything:
        # review-api answers an unknown PR with an empty list, not a 404, so
        # a mistyped id and a clean PR look the same from here.
        print(f"cascadesec: review-api has no findings for {pr_id}; if that is unexpected, "
              "check the id against the dashboard's URL", file=sys.stderr)
    shown = review.filter_findings(everything, set(args.status or ()), args.severity, args.file)
    return {
        "pr_id": pr_id,
        "count": len(everything),
        "matched": len(shown),
        "findings": sorted(shown, key=review.sort_key),
        # For the table only; _emit drops keys that start with "_".
        "_all": everything,
        "_filtered": bool(args.status or args.severity or args.file),
    }


def cmd_show(args, ctx):
    pr_id = prs.resolve(args.pr, ctx.env)
    client = ctx.client()
    finding, listing = _find(client, pr_id, args.finding_id)

    fix = finding.get("proposed_fix") or {}
    unmet = []
    if fix.get("applies_after"):
        if listing is None:
            listing = client.get("prs", pr_id, "findings").get("findings") or []
        unmet = review.unmet_prerequisites(fix["applies_after"], {f["finding_id"]: f for f in listing})
    events = client.get("prs", pr_id, "findings", finding["finding_id"], "events").get("events") or []
    return {
        "pr_id": pr_id,
        "finding": finding,
        "unmet_prerequisites": unmet,
        "events": sorted(events, key=lambda e: e.get("created_at", "")),
        "_agent_diff": args.agent_diff,
    }


def _find(client, pr_id, wanted):
    """(finding, the PR's listing or None). A full id is fetched alone; a
    prefix needs the listing to be resolved, and the caller may reuse it."""
    wanted = wanted.strip().lower()
    if FULL_FINDING_ID.match(wanted):
        try:
            return client.get("prs", pr_id, "findings", wanted), None
        except api.ApiError as e:
            if e.status == 404:
                raise CliError(f"{pr_id} has no finding {wanted}", USAGE) from None
            raise
    listing = client.get("prs", pr_id, "findings").get("findings") or []
    return _by_prefix(listing, wanted, pr_id), listing


def cmd_approve(args, ctx):
    return _decide(args, ctx, "approved")


def cmd_reject(args, ctx):
    return _decide(args, ctx, "rejected")


def _decide(args, ctx, action, finding=None, client=None, pr_id=None, edited_content=None):
    """POST the decision; review-api checks prerequisites, statuses and who
    may decide. Nothing here pre-empts it (§10): the API is the rule."""
    if finding is None:
        pr_id = prs.resolve(args.pr, ctx.env)
        client = ctx.client()
        finding, _ = _find(client, pr_id, args.finding_id)
    body = {"action": action, "notes": args.notes}
    if edited_content is not None:
        body["edited_content"] = edited_content
    try:
        reply = client.request("POST", "prs", pr_id, "findings", finding["finding_id"], "review",
                               body=body)
    except api.ApiError as e:
        unmet = e.body.get("unmet") if isinstance(e.body, dict) else None
        if e.status == 409 and unmet:
            raise CliError(_unmet_message(action, pr_id, finding, unmet), REFUSED) from None
        raise
    return {
        "pr_id": pr_id,
        "finding_id": finding["finding_id"],
        "rule": f"{finding['source']} {finding['rule_id']}",
        "location": review.location(finding),
        "action": reply.get("action", action),
        "status": reply.get("status"),
        "recorded_at": reply.get("recorded_at"),
        # Named by the API so the reviewer who caused the cascade hears of it
        # now, not later in someone else's queue (§10).
        "reopened_dependents": reply.get("reopened_dependents") or [],
        "recorded": True,
    }


def _unmet_message(action, pr_id, finding, unmet):
    verb = {"approved": "approve", "edited": "edit"}.get(action, action)
    lines = [f"cannot {verb} {finding['finding_id']}: it is drafted on fixes that are not settled"]
    for u in unmet:
        why = review.UNMET_EXPLANATION.get(u.get("reason"), u.get("reason") or "is not settled")
        lines.append(f"  - {u.get('finding_id')} {why}")
        lines.append(f"      cascadesec show {pr_id} {u.get('finding_id')}")
    lines.append(f"Settle those first, or refuse this one: `cascadesec reject {pr_id} "
                 f"{finding['finding_id']}` is never blocked.")
    return "\n".join(lines)


def cmd_edit(args, ctx):
    pr_id = prs.resolve(args.pr, ctx.env)
    client = ctx.client()
    finding, _ = _find(client, pr_id, args.finding_id)
    fid = finding["finding_id"]
    if not finding.get("proposed_fix"):
        raise CliError(f"{fid} has no proposed fix to edit (status {finding.get('status')})", REFUSED)
    if not args.file and not ctx.interactive:
        raise CliError("edit opens an editor, which needs a terminal; pass --file PATH to send "
                       "a prepared file", USAGE)

    current = client.get("prs", pr_id, "findings", fid, "content")
    draft = None
    if args.file:
        edited = editor.read_prepared(args.file)
    else:
        draft = editor.Draft(current["file"], current["content"])
        edited = draft.open(ctx.env, run=ctx.run)

    if edited == current["content"]:
        if draft:
            draft.discard()
        hint = "" if args.file else " (a GUI editor needs its wait flag, e.g. EDITOR='code --wait')"
        print(f"cascadesec: no changes, so nothing was recorded{hint}", file=sys.stderr)
        return {"pr_id": pr_id, "finding_id": fid, "recorded": False}

    kept = f" Your edit is at {draft.path}." if draft else ""
    err = render.Out(sys.stderr, color=sys.stderr.isatty() and "NO_COLOR" not in ctx.env)
    err.line(f"Your change to the fix for {fid} ({current['file']}):")
    render.diff_lines(err, "".join(difflib.unified_diff(
        current["content"].splitlines(keepends=True), edited.splitlines(keepends=True),
        fromfile=f"fix/{current['file']}", tofile=f"edited/{current['file']}")))
    if not args.yes:
        if not ctx.interactive:
            raise CliError("--yes is needed to record an edit without a terminal." + kept, USAGE)
        if ctx.prompt("Record this as your edit of the fix? [y/N] ").strip().lower() not in ("y", "yes"):
            print("cascadesec: nothing recorded." + kept, file=sys.stderr)
            return {"pr_id": pr_id, "finding_id": fid, "recorded": False}

    try:
        result = _decide(args, ctx, "edited", finding=finding, client=client, pr_id=pr_id,
                         edited_content=edited)
    except CliError as e:
        if draft:
            raise CliError(f"{e}\n{kept.strip()} Send it again with "
                           f"`cascadesec edit {pr_id} {fid} --file {draft.path}`.", e.code) from None
        raise
    if draft:
        draft.discard()
    return result


def cmd_commit(args, ctx):
    pr_id = prs.resolve(args.pr, ctx.env)
    client = ctx.client()
    expected = committing.parse_expect(args.expect_sha) if args.expect_sha else None
    try:
        plan = client.get("prs", pr_id, "commit-plan")
    except api.ApiError as e:
        if e.status == 404:
            raise CliError(f"{pr_id}: {e}", USAGE) from None
        raise
    summary = {"pr_id": pr_id, "repository": plan.get("repository"),
               "pr_number": plan.get("pr_number")}

    # The plan is what is being confirmed, so it is printed before any
    # question, and before any refusal it already implies (§10).
    render.commit_plan(plan, ctx.stderr())
    who = auth.claims(auth.current_session(ctx.settings, ctx.store())["id_token"]).get("email") or "you"
    reason = committing.refusal_before_prompt(plan, who)
    if reason:
        raise CliError(reason, REFUSED)
    if not committing.to_commit(plan):
        return {**summary, "status": "nothing-to-commit", "recorded": False}

    if not ctx.interactive and not (args.yes and expected is not None):
        raise CliError("without a terminal, commit needs --yes and an --expect-sha FILE=SHA for "
                       "each file it commits (the sha256 lines above), so a script can only "
                       "confirm content it was told about", USAGE)
    confirm = committing.confirmation(plan, expected)
    if not args.yes:
        n = len(confirm)
        question = (f"Commit {n} file{'' if n == 1 else 's'} to "
                    f"{plan['repository']}#{plan['pr_number']}, as shown? [y/N] ")
        if ctx.prompt(question).strip().lower() not in ("y", "yes"):
            print("cascadesec: nothing committed.", file=sys.stderr)
            return {**summary, "status": None, "recorded": False}

    request_id = committing.request(client, pr_id, confirm)
    if args.no_wait:
        return {**summary, "request_id": request_id, "status": "requested"}
    record = committing.wait(client, pr_id, request_id, timeout=args.timeout,
                             sleep=ctx.sleep, now=ctx.clock)
    return {**summary, **{k: record.get(k) for k in
                          ("request_id", "status", "reason", "commit_sha", "files", "requested_by")},
            "_exit": committing.outcome_code(record)}


def _hold_back(args, ctx, result, image_ref, settings, path, document):
    """What leaves the verdict, in order: apps skip_apps names, everything
    outside --changed-only, then baselined findings. Each is counted, so
    nothing leaves silently (cli-spec §6). The baseline's fixed list is
    taken from the full scan, before --changed-only: a finding in a file
    nobody touched has not been fixed for having been left out."""
    full = result.get("findings") or []
    result, skipped = baseline.skip_apps(result, args.path, settings.skip_apps)

    outside = 0
    if args.changed_only:
        changed = baseline.changed_files(args.path, args.changed_only, run=ctx.run)
        result, outside = baseline.scope_to_changes(result, changed)

    kept, suppressed, _ = baseline.apply(result.get("findings") or [], document)
    _, _, fixed = baseline.apply(full, document)
    if document is not None and not baseline.same_image(document, image_ref):
        print(f"cascadesec: the baseline was written with {document.get('scanner_image')}, and this "
              f"scan ran {image_ref}; a newer rule version can fire findings that are not "
              "regressions", file=sys.stderr)
    return {**result, "findings": kept}, {
        "baseline": str(path) if document is not None else None,
        "baselined_count": len(suppressed),
        "baseline_fixed": fixed,
        "changed_only": args.changed_only,
        "outside_changes_count": outside,
        "skipped_apps": [{k: a[k] for k in ("path", "kind", "reason", "source")} for a in skipped],
    }


def cmd_hook(args, ctx):
    root = ctx._cwd or os.getcwd()
    if not args.files:
        return {"hook_files": [], "exit_code": 0, "_exit": 0, "_nothing": True}
    settings = config.load(cwd=root, env=ctx.env)
    path = args.baseline or baseline.default_path(root)
    if args.baseline and not os.path.isfile(path):
        raise CliError(f"--baseline {args.baseline}: no such file", USAGE)
    image_ref = ("this container" if ctx.env.get("CASCADESEC_IN_IMAGE") == "1"
                 else scanning.image(args.image, ctx.env))
    summary = hook.run(args.files, root, image_ref, args.fail_on, args.allow_scan_errors,
                       path if os.path.isfile(path) else None, skips=settings.skip_apps, run=ctx.run,
                       in_image=ctx.env.get("CASCADESEC_IN_IMAGE") == "1")
    return {**summary, "path": ".", "_exit": summary["exit_code"]}


def cmd_baseline(args, ctx):
    image_ref = scanning.image(args.image, ctx.env)
    if not os.path.isdir(args.path):
        raise CliError(f"{args.path} is not a directory", USAGE)
    target = args.file or baseline.default_path(args.path)
    existing = baseline.load(target)
    if args.prune and existing is None:
        raise CliError(f"{target}: no baseline to prune; write one with `cascadesec baseline`", USAGE)
    print(f"cascadesec: scanning {os.path.abspath(args.path)} in {image_ref} (no network)",
          file=sys.stderr)
    result = scanning.run_scanner(args.path, image_ref, run=ctx.run)
    findings = result.get("findings") or []
    entries = baseline.prune(existing, findings) if args.prune else baseline.entries_for(findings)
    before = {e["fingerprint"] for e in (existing or {}).get("findings", [])}
    after = {e["fingerprint"] for e in entries}
    baseline.write(target, entries, image_ref)
    incomplete = bool(result.get("scan_errors") or result.get("unscanned_apps"))
    if incomplete:
        print("cascadesec: the scan was incomplete, so the baseline holds nothing for the files "
              "that did not parse or the apps that were not run; their findings will appear as new "
              "once they are scanned", file=sys.stderr)
    return {"baseline": str(target), "entries": len(entries), "added": len(after - before),
            "removed": len(before - after), "scanner_image": image_ref, "scan_incomplete": incomplete}


def _ask(text):
    sys.stderr.write(text)
    sys.stderr.flush()
    return input()


def _by_prefix(findings, prefix, pr_id):
    if not prefix:
        raise CliError("give a finding id", USAGE)
    matches = [f for f in findings if f["finding_id"].startswith(prefix)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise CliError(f"{pr_id} has no finding starting {prefix!r}", USAGE)
    listed = ", ".join(sorted(f["finding_id"] for f in matches)[:5])
    raise CliError(f"{prefix!r} matches {len(matches)} findings on {pr_id} ({listed}"
                   f"{', ...' if len(matches) > 5 else ''}); give more of the id", USAGE)


COMMANDS = {
    "login": cmd_login,
    "logout": cmd_logout,
    "whoami": cmd_whoami,
    "version": cmd_version,
    "findings": cmd_findings,
    "show": cmd_show,
    "approve": cmd_approve,
    "reject": cmd_reject,
    "edit": cmd_edit,
    "commit": cmd_commit,
    "scan": cmd_scan,
    "baseline": cmd_baseline,
    "hook": cmd_hook,
}

# Commands whose table format is more than key/value lines.
RENDERERS = {
    "findings": lambda result, out: render.findings(
        {**result, "all_findings": result["_all"], "filtered": result["_filtered"]}, out),
    "show": lambda result, out: render.show({**result, "agent_diff": result["_agent_diff"]}, out),
    "approve": lambda result, out: render.decision(result, out),
    "reject": lambda result, out: render.decision(result, out),
    "edit": lambda result, out: render.decision(result, out),
    "commit": lambda result, out: render.commit_result(result, out),
    "scan": lambda result, out: render.scan_result(result, out),
    "baseline": lambda result, out: render.baseline_result(result, out),
    "hook": lambda result, out: render.hook_result(result, out),
}


# ---------- output ----------

TABLE_LABELS = {
    "signed_in_as": "Signed in as",
    "signed_out": "Signed out",
    "revoked": "Revoked",
    "email": "Signed in as",
    "groups": "Groups",
    "token_issued_at": "Token issued",
    "token_expires_at": "Token expires",
    "signed_in_at": "Signed in",
    "deployment": "Deployment",
    "cli": "cascadesec",
    "scanner_image": "Scanner image",
    "baseline": "Baseline",
    "entries": "Entries",
    "added": "Added",
    "removed": "Removed",
    "scan_incomplete": "Scan incomplete",
}


def _emit(result, fmt, stdout):
    result = {k: v for k, v in result.items() if not k.startswith("_")}
    if fmt == "json":
        stdout.write(json.dumps(result, indent=2) + "\n")
        return
    width = max(len(TABLE_LABELS.get(k, k)) for k in result)
    for key, value in result.items():
        if isinstance(value, list):
            value = ", ".join(value) or "(none)"
        elif isinstance(value, bool):
            value = "yes" if value else "no"
        elif value is None:
            value = "-"
        stdout.write(f"{TABLE_LABELS.get(key, key):<{width}}  {value}\n")


def _iso(epoch):
    if not epoch:
        return None
    return datetime.fromtimestamp(int(epoch)).astimezone().isoformat(timespec="minutes")


if __name__ == "__main__":
    sys.exit(main())
