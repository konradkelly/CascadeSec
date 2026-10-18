"""`cascadesec`: the command line (docs/cli-spec.md §2).

Built so far: track R's first three steps (§13) -- the skeleton, signing a
person in, and reading a PR's findings (`findings`, `show`). Commands that
don't exist yet aren't registered, so `--help` lists only what works.

Results go to stdout in --format; progress, prompts and errors go to stderr,
so `--format json` output can be piped whatever else is printed.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

from cascadesec import __version__, api, auth, config, prs, render, review
from cascadesec.errors import OK, USAGE, CliError
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
    return parser


def main(argv=None, *, stdout=None, env=None, cwd=None, backend=None):
    if stdout is None:
        stdout = sys.stdout
        # A finding's title or a fix's rationale may hold characters the
        # console's code page lacks; print them as `?` rather than crash.
        if hasattr(stdout, "reconfigure"):
            stdout.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    fmt = args.format or ("table" if stdout.isatty() else "json")
    ctx = _Context(env, cwd, backend)
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

    def __init__(self, env, cwd, backend):
        self._env, self._cwd, self._backend = env, cwd, backend
        self._settings = None

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
    wanted = args.finding_id.strip().lower()
    listing = None
    if FULL_FINDING_ID.match(wanted):
        try:
            finding = client.get("prs", pr_id, "findings", wanted)
        except api.ApiError as e:
            if e.status == 404:
                raise CliError(f"{pr_id} has no finding {wanted}", USAGE) from None
            raise
    else:
        listing = client.get("prs", pr_id, "findings").get("findings") or []
        finding = _by_prefix(listing, wanted, pr_id)

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
}

# Commands whose table format is more than key/value lines.
RENDERERS = {
    "findings": lambda result, out: render.findings(
        {**result, "all_findings": result["_all"], "filtered": result["_filtered"]}, out),
    "show": lambda result, out: render.show({**result, "agent_diff": result["_agent_diff"]}, out),
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
