"""`cascadesec`: the command line (docs/cli-spec.md §2).

Built so far: track R's first four steps (§13) -- the skeleton, signing a
person in, reading a PR's findings (`findings`, `show`), and deciding on a
fix (`approve`, `reject`, `edit`). Commands that don't exist yet aren't
registered, so `--help` lists only what works.

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
from datetime import datetime

from cascadesec import __version__, api, auth, config, editor, prs, render, review
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
    commands.add_parser("version", help="the CLI's version")

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
    return parser


def main(argv=None, *, stdout=None, env=None, cwd=None, backend=None,
         prompt=None, interactive=None, run=None):
    if stdout is None:
        stdout = sys.stdout
        # A finding's title or a fix's rationale may hold characters the
        # console's code page lacks; print them as `?` rather than crash.
        if hasattr(stdout, "reconfigure"):
            stdout.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    fmt = args.format or ("table" if stdout.isatty() else "json")
    ctx = _Context(env, cwd, backend, prompt=prompt, interactive=interactive, run=run)
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
    return OK


class _Context:
    """Settings and the session store, loaded on first use: `version` needs
    neither, and shouldn't fail on a broken config file."""

    def __init__(self, env, cwd, backend, prompt=None, interactive=None, run=None):
        self._env, self._cwd, self._backend = env, cwd, backend
        self._settings = None
        # Questions go to stderr like every other prompt, so a confirmation
        # never lands in --format json output.
        self.prompt = prompt or _ask
        self.interactive = sys.stdin.isatty() if interactive is None else interactive
        self.run = run or subprocess.run

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
    return {"cli": __version__}


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
}

# Commands whose table format is more than key/value lines.
RENDERERS = {
    "findings": lambda result, out: render.findings(
        {**result, "all_findings": result["_all"], "filtered": result["_filtered"]}, out),
    "show": lambda result, out: render.show({**result, "agent_diff": result["_agent_diff"]}, out),
    "approve": lambda result, out: render.decision(result, out),
    "reject": lambda result, out: render.decision(result, out),
    "edit": lambda result, out: render.decision(result, out),
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
