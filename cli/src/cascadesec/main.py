"""`cascadesec`: the command line (docs/cli-spec.md §2).

Built so far: track R's first two steps (§13) -- the skeleton, and signing a
person in. Commands that don't exist yet aren't registered, so `--help`
lists only what works.

Results go to stdout in --format; progress, prompts and errors go to stderr,
so `--format json` output can be piped whatever else is printed.
"""

import argparse
import json
import sys
from datetime import datetime

from cascadesec import __version__, auth, config
from cascadesec.errors import OK, USAGE, CliError
from cascadesec.store import SessionStore


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
    return parser


def main(argv=None, *, stdout=None, env=None, cwd=None, backend=None):
    stdout = stdout or sys.stdout
    args = build_parser().parse_args(argv)
    fmt = args.format or ("table" if stdout.isatty() else "json")
    try:
        result = COMMANDS[args.command](args, _Context(env, cwd, backend))
    except CliError as e:
        print(f"cascadesec: {e}", file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        print("cascadesec: interrupted", file=sys.stderr)
        return USAGE
    _emit(result, fmt, stdout)
    return OK


class _Context:
    """Settings and the session store, loaded on first use: `version` needs
    neither, and shouldn't fail on a broken config file."""

    def __init__(self, env, cwd, backend):
        self._env, self._cwd, self._backend = env, cwd, backend
        self._settings = None

    @property
    def settings(self):
        if self._settings is None:
            self._settings = config.load(cwd=self._cwd, env=self._env)
        return self._settings

    def store(self):
        s = self.settings.require("auth_domain", "client_id")
        kwargs = {"backend": self._backend} if self._backend else {}
        return SessionStore(s.auth_domain, s.client_id, **kwargs)


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


COMMANDS = {
    "login": cmd_login,
    "logout": cmd_logout,
    "whoami": cmd_whoami,
    "version": cmd_version,
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
