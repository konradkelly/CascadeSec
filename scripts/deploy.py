#!/usr/bin/env python3
"""Plan a deploy, refuse what nobody meant, and apply only the plan that was read.

  python scripts/deploy.py                              # check, plan, summarise; applies nothing
  python scripts/deploy.py --allow-destroy ADDRESS      # ...when a destroy is intended
  python scripts/deploy.py --apply-saved                # apply exactly the plan just reviewed

Written after one apply on 2026-10-11 did two things nobody intended. It
was run with no terraform.tfvars, so Terraform prompted for github_app_id
and took "yes" as its value, and github-gateway signed every GitHub call
with an invalid issuer for five days. And with github_writer_app_id unset,
the write-back resources it counts on went to zero, so the apply destroyed
github-committer. Write-back stayed down for a week, until
`cascadesec commit` found it. The deploy instructions said to expect only
one Lambda to change, which was a guess and not a plan anyone had read.

So this script checks, in order, and stops at the first failure:

  1. terraform.tfvars sets every variable that gates resources
     (REQUIRED_VARIABLES). A missing one is named, with what it would cost.
  2. The code Terraform packages from disk -- the root's *.tf and every
     lambda/*/handler.py -- matches --ref (default origin/main). archive_file
     zips whatever is on disk, so an uncommitted edit would otherwise ship
     without anyone deciding to. --allow-local-changes overrides it.
  3. `terraform plan -input=false`: a variable that is still missing is an
     error, never a prompt.
  4. The plan's real changes, read from `terraform show -json`: what it
     creates, updates and destroys. A destroy or a replace that
     --allow-destroy does not name stops the run with a non-zero exit, so
     an unexpected one cannot read as drift.

It applies nothing unless asked. `--apply-saved` re-reads the saved plan,
runs step 4 on it again, and applies that file, so what is applied is
byte-for-byte the plan that was reviewed. Terraform itself refuses a saved
plan once the state has moved on since it was made.

Needs terraform on PATH and git. Run from anywhere; --terraform-dir points
at the root that holds the state (default: this repository's terraform/).
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLAN_FILE = "deploy.tfplan"

# Variables that gate resources: unset, a feature is not merely off, it is
# destroyed. Each says what its absence costs, because that is the message.
REQUIRED_VARIABLES = {
    "github_app_id": "github-gateway's App id. Missing, an interactive apply prompts for it, and "
                     "whatever is typed becomes the JWT issuer (2026-10-11: 'yes').",
    "alarm_email": "the alarms topic's only subscriber. Missing, every alarm fires to nobody.",
    "github_writer_app_id": "the CascadeSec Fixes App (write-back). Missing, github-committer and "
                            "everything counted on local.write_back_enabled is destroyed.",
}


class Stop(Exception):
    """A check failed; the message is what to tell the person."""


# ---------- 1. variables ----------

TFVAR = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$')


def tfvars_values(text):
    """Top-level `name = value` pairs from an HCL tfvars file. Only what the
    check needs: simple assignments, comments skipped, quotes removed."""
    values = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].split("//", 1)[0]
        match = TFVAR.match(line)
        if match:
            values[match[1]] = match[2].strip().strip('"')
    return values


def check_variables(terraform_dir):
    path = terraform_dir / "terraform.tfvars"
    if not path.is_file():
        raise Stop(f"{path} does not exist. It holds the values below; without it, every one of "
                   "them is missing:\n" + _variables_help(REQUIRED_VARIABLES))
    values = tfvars_values(path.read_text(encoding="utf-8"))
    missing = {k: why for k, why in REQUIRED_VARIABLES.items() if not values.get(k)}
    if missing:
        raise Stop(f"{path} does not set:\n" + _variables_help(missing))
    return values


def _variables_help(variables):
    return "\n".join(f"  - {name}: {why}" for name, why in variables.items())


# ---------- 2. the code Terraform packages ----------

def packaged_paths(repo):
    """Repository-relative paths Terraform reads from disk into a deploy."""
    paths = sorted(p for p in (repo / "terraform").glob("*.tf"))
    paths += sorted((repo / "lambda").glob("*/handler.py"))
    return [p.relative_to(repo).as_posix() for p in paths]


def _normalise(data):
    return data.replace(b"\r\n", b"\n")


def check_code(repo, ref, git=subprocess.run):
    """Paths whose working-tree content differs from `ref`, ignoring CRLF
    against LF (a Windows checkout differs only in that)."""
    differs = []
    for path in packaged_paths(repo):
        shown = git(["git", "-C", str(repo), "show", f"{ref}:{path}"], capture_output=True)
        on_disk = _normalise((repo / path).read_bytes())
        if shown.returncode != 0:
            differs.append(f"{path} (not in {ref})")
        elif _normalise(shown.stdout) != on_disk:
            differs.append(path)
    if differs:
        raise Stop(f"the code Terraform would package is not {ref}'s:\n"
                   + "\n".join(f"  - {d}" for d in differs)
                   + f"\nCommit it, check out {ref}, or pass --allow-local-changes if shipping "
                     "this working tree is the point.")


# ---------- 3, 4. the plan ----------

def summarise(plan_json):
    """{creates, updates, replaces, destroys}: lists of resource addresses,
    from `terraform show -json`'s resource_changes. Reads and no-ops are
    not changes."""
    summary = {"creates": [], "updates": [], "replaces": [], "destroys": []}
    for change in plan_json.get("resource_changes") or []:
        actions = change.get("change", {}).get("actions") or []
        address = change.get("address", "?")
        if "delete" in actions and "create" in actions:
            summary["replaces"].append(address)
        elif "delete" in actions:
            summary["destroys"].append(address)
        elif "create" in actions:
            summary["creates"].append(address)
        elif "update" in actions:
            summary["updates"].append(address)
    return summary


def unexpected_destroys(summary, allowed):
    """Destroys and replaces nobody named. A replace destroys first, so it
    counts: a Lambda replaced is a Lambda briefly gone."""
    return [a for a in summary["destroys"] + summary["replaces"] if a not in allowed]


def report(summary, out=print):
    counts = ", ".join(f"{len(v)} {k[:-1] if len(v) == 1 else k}"
                       for k, v in summary.items())
    out(f"plan: {counts}")
    for kind, mark in (("destroys", "-"), ("replaces", "-/+"), ("creates", "+"), ("updates", "~")):
        for address in summary[kind]:
            out(f"  {mark:>3} {address}")


def terraform(args, terraform_dir, run=subprocess.run, capture=False):
    result = run(["terraform", f"-chdir={terraform_dir}", *args], capture_output=capture, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() if capture else ""
        raise Stop(f"terraform {args[0]} failed" + (f":\n{detail}" if detail else ""))
    return result.stdout if capture else None


def read_plan(terraform_dir, run=subprocess.run):
    return summarise(json.loads(terraform(["show", "-json", PLAN_FILE], terraform_dir, run, capture=True)))


def check_plan(summary, allowed):
    unexpected = unexpected_destroys(summary, allowed)
    if unexpected:
        raise Stop("the plan destroys what nobody said to destroy:\n"
                   + "\n".join(f"  - {a}" for a in unexpected)
                   + "\nIf a variable is missing, that is usually why (step 1 lists the ones that "
                     "gate resources). If the destroy is intended, name each address with "
                     "--allow-destroy.")


# ---------- the run ----------

def main(argv=None, run=subprocess.run, out=print):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--terraform-dir", type=Path, default=REPO / "terraform",
                    help="the Terraform root holding the state (default: this repository's terraform/)")
    ap.add_argument("--ref", default="origin/main",
                    help="the git ref the packaged code must match (default origin/main)")
    ap.add_argument("--allow-local-changes", action="store_true",
                    help="deploy the working tree's code even where it differs from --ref")
    ap.add_argument("--allow-destroy", action="append", default=[], metavar="ADDRESS",
                    help="a resource address the plan may destroy or replace; repeat for each")
    ap.add_argument("--apply-saved", action="store_true",
                    help=f"apply {PLAN_FILE}, the plan the last run wrote, after checking it again")
    args = ap.parse_args(argv)
    terraform_dir = args.terraform_dir.resolve()
    repo = terraform_dir.parent

    try:
        if args.apply_saved:
            if not (terraform_dir / PLAN_FILE).is_file():
                raise Stop(f"no {PLAN_FILE} in {terraform_dir}; run this script without --apply-saved first")
            summary = read_plan(terraform_dir, run)
            report(summary, out)
            check_plan(summary, set(args.allow_destroy))
            out(f"applying {PLAN_FILE}, the plan above")
            terraform(["apply", "-input=false", PLAN_FILE], terraform_dir, run)
            (terraform_dir / PLAN_FILE).unlink(missing_ok=True)
            return 0

        check_variables(terraform_dir)
        out("variables: " + ", ".join(REQUIRED_VARIABLES) + " are set")
        if args.allow_local_changes:
            out("code: not compared (--allow-local-changes)")
        else:
            run(["git", "-C", str(repo), "fetch", "--quiet", "origin"], capture_output=True)
            check_code(repo, args.ref, git=run)
            out(f"code: the packaged .tf and handlers match {args.ref}")
        terraform(["plan", "-input=false", "-out", PLAN_FILE], terraform_dir, run)
        summary = read_plan(terraform_dir, run)
        report(summary, out)
        check_plan(summary, set(args.allow_destroy))
        out(f"saved as {terraform_dir / PLAN_FILE}. Read the plan above; to apply exactly it:\n"
            f"  python {Path(__file__).as_posix()} --terraform-dir {terraform_dir.as_posix()} --apply-saved"
            + "".join(f" --allow-destroy {a}" for a in args.allow_destroy))
        return 0
    except Stop as e:
        print(f"deploy: stopped. {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
