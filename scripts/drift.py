#!/usr/bin/env python3
"""Compare what is deployed with the repository, and change nothing deployed.

  python scripts/drift.py                     # every check, against origin/main
  python scripts/drift.py --skip dashboard    # ...without building the dashboard

docs/completion.md phase 1 step 5. Four things reach AWS, and three of them
by a step of their own outside `terraform apply`, so each has drifted
unnoticed before (the deployed corpus was found stale on 2026-10-11):

  corpus     s3://<artifacts>/corpus/, which corpus/upload.sh syncs and
             mapping-agent reads, against --ref's corpus/frameworks and
             rule_mappings.json.
  scanner    the iac-scanner Lambda's image against ECR's `latest`, against
             the digest the CLI pins (SCANNER_IMAGE), and against --ref:
             build-image.sh tags each image with its commit, and no file
             the Dockerfile copies may have changed on --ref since.
  dashboard  the dashboard bucket against a build of --ref's dashboard/,
             made in a scratch directory with `npm ci`, and the build-time
             values the deployed stack's outputs give.
  terraform  scripts/deploy.py's checks, then a plan of everything Terraform
             packages, which must have no changes.

Every check runs and says what differs. Exit 0 when all are clean, 1 when
any is not or could not be checked.

Nothing deployed is written. S3 and ECR are listed and read, the Lambda is
described, and the plan is saved as drift.tfplan and deleted afterwards, so
a deploy.tfplan waiting to be applied is left alone. Locally it does what
deploy.py does before a plan, and assembles build/<function>/.

What it cannot see: the scanner image is judged by the commit it is tagged
with, and build-image.sh builds from the working tree, so an image built
with uncommitted changes would pass.

Needs terraform, git, npm, boto3, and AWS credentials that can read the
stack. Run from anywhere; --terraform-dir as for deploy.py.
"""

import argparse
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import deploy  # noqa: E402
from deploy import Stop  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
PLAN_FILE = "drift.tfplan"
CHECKS = ("corpus", "scanner", "dashboard", "terraform")

# What corpus/upload.sh puts under s3://<artifacts>/corpus/. test_drift.py
# holds this to the script.
CORPUS = ("corpus/frameworks", "corpus/rule_mappings.json")

# What the scanner image is built from: the Dockerfile and what it copies.
# test_drift.py holds this to the Dockerfile's COPY lines.
SCANNER_INPUTS = (
    "lambda/iac-scanner/Dockerfile",
    "lambda/iac-scanner/checks",
    "lambda/iac-scanner/handler.py",
    "lambda/iac-scanner/local_main.py",
    "corpus/frameworks",
    "corpus/rule_mappings.json",
)
SCANNER_PIN = "cli/src/cascadesec/scan.py"


# ---------- comparing files ----------

def compare(expected, deployed, read):
    """What differs between {key: bytes} from the repository and {key: ETag}
    deployed. A matching ETag is the object's MD5, so it is not read. Any
    other is read and compared with line endings normalised, as deploy.py
    does: an upload from a Windows checkout may carry CRLF."""
    problems = []
    for key in sorted(expected):
        if key not in deployed:
            problems.append(f"not deployed: {key}")
        elif deployed[key].strip('"') != hashlib.md5(expected[key]).hexdigest() \
                and deploy._normalise(read(key)) != deploy._normalise(expected[key]):
            problems.append(f"differs: {key}")
    problems += [f"deployed, not in the repository: {key}" for key in sorted(set(deployed) - set(expected))]
    return problems


def list_bucket(s3, bucket, prefix=""):
    """{key: ETag} for every object under prefix."""
    objects, token = {}, None
    while True:
        page = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, **({"ContinuationToken": token} if token else {}))
        objects.update({o["Key"]: o["ETag"] for o in page.get("Contents", [])})
        token = page.get("NextContinuationToken")
        if not token:
            return objects


def reader(s3, bucket):
    return lambda key: s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def git_files(ref, paths, run, repo=REPO):
    """{path: bytes} at ref, for every file under paths."""
    listed = run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", ref, "--", *paths], capture_output=True)
    if listed.returncode != 0:
        raise Stop(f"git cannot list {', '.join(paths)} at {ref}")
    files = {}
    for path in listed.stdout.decode().splitlines():
        shown = run(["git", "-C", str(repo), "show", f"{ref}:{path}"], capture_output=True)
        if shown.returncode != 0:
            raise Stop(f"git cannot show {ref}:{path}")
        files[path] = shown.stdout
    return files


# ---------- the checks ----------

def check_corpus(ref, outputs, aws, run):
    bucket = outputs["artifacts_bucket_name"]
    s3 = aws["s3"]
    return compare(git_files(ref, CORPUS, run), list_bucket(s3, bucket, "corpus/"), reader(s3, bucket))


def check_scanner(ref, outputs, aws, run):
    code = aws["lambda"].get_function(FunctionName=outputs["iac_scanner_function_name"])["Code"]
    running = _digest(code.get("ResolvedImageUri") or code.get("ImageUri") or "")
    if running is None:
        raise Stop(f"the Lambda's image is not named by digest: {code.get('ImageUri')!r}")
    repository = outputs["scanner_ecr_repository_url"].split("/", 1)[1]
    ecr = aws["ecr"]
    problems = []

    latest = ecr.describe_images(repositoryName=repository, imageIds=[{"imageTag": "latest"}])
    latest = latest["imageDetails"][0]["imageDigest"]
    if latest != running:
        problems.append(f"the Lambda runs {running}, and ECR's latest is {latest}: the next apply rolls it")

    pin = run(["git", "-C", str(REPO), "show", f"{ref}:{SCANNER_PIN}"], capture_output=True)
    pinned = re.search(r"SCANNER_IMAGE\s*=.*?(sha256:[0-9a-f]{64})", pin.stdout.decode(), re.S) \
        if pin.returncode == 0 else None
    if pinned is None:
        problems.append(f"no SCANNER_IMAGE digest in {ref}:{SCANNER_PIN}")
    elif pinned[1] != running:
        problems.append(f"the CLI pins {pinned[1]} ({SCANNER_PIN}), and the Lambda runs {running}")

    try:
        tags = ecr.describe_images(repositoryName=repository,
                                   imageIds=[{"imageDigest": running}])["imageDetails"][0].get("imageTags", [])
    except ecr.exceptions.ImageNotFoundException:
        tags = None
    commits = [t for t in tags or [] if re.fullmatch(r"[0-9a-f]{7,40}", t)]
    if tags is None:
        problems.append(f"ECR no longer holds {running}, so what it was built from is unknown")
    elif not commits:
        problems.append(f"{running} carries no commit tag, so what it was built from is unknown")
    else:
        problems += _changed_since(commits, ref, run)
    return problems


def _digest(uri):
    match = re.search(r"@(sha256:[0-9a-f]{64})$", uri)
    return match[1] if match else None


def _changed_since(commits, ref, run):
    """Nothing, when any of the image's commits has --ref's scanner inputs;
    otherwise what changed since the newest one git knows."""
    for commit in commits:
        diff = run(["git", "-C", str(REPO), "diff", "--name-only", commit, ref, "--", *SCANNER_INPUTS],
                   capture_output=True)
        if diff.returncode != 0:
            continue
        changed = diff.stdout.decode().split()
        if not changed:
            return []
        return [f"the image was built from {commit}, and on {ref} since then: {', '.join(changed)}"]
    return [f"git does not know the image's commit ({', '.join(commits)})"]


def dashboard_env(outputs):
    """dashboard/.env as a deploy of this stack needs it (.env.example)."""
    return (f"VITE_API_BASE_URL={outputs['review_api_endpoint'].rstrip('/')}\n"
            f"VITE_COGNITO_DOMAIN={outputs['cognito_hosted_ui_domain']}\n"
            f"VITE_COGNITO_CLIENT_ID={outputs['cognito_dashboard_client_id']}\n")


def build_dashboard(ref, outputs, run, work):
    """{path: bytes} of dist/, built from ref's dashboard/ alone: exported
    with git archive, so nothing in the working tree reaches it."""
    archive = run(["git", "-C", str(REPO), "archive", "--format=tar", ref, "dashboard"], capture_output=True)
    if archive.returncode != 0:
        raise Stop(f"git cannot export {ref}:dashboard")
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(work, filter="data")
    source = work / "dashboard"
    (source / ".env").write_text(dashboard_env(outputs), encoding="utf-8")
    npm = shutil.which("npm")
    if npm is None:
        raise Stop("npm is not on PATH")
    for step in (["ci", "--no-audit", "--no-fund"], ["run", "build"]):
        built = run([npm, *step], cwd=source, capture_output=True, text=True)
        if built.returncode != 0:
            raise Stop(f"npm {' '.join(step)} failed:\n{(built.stderr or built.stdout).strip()[-2000:]}")
    dist = source / "dist"
    return {p.relative_to(dist).as_posix(): p.read_bytes() for p in sorted(dist.rglob("*")) if p.is_file()}


def check_dashboard(ref, outputs, aws, run):
    bucket = outputs["dashboard_bucket_name"]
    with tempfile.TemporaryDirectory(prefix="drift-", ignore_cleanup_errors=True) as work:
        built = build_dashboard(ref, outputs, run, Path(work))
    s3 = aws["s3"]
    return compare(built, list_bucket(s3, bucket), reader(s3, bucket))


def check_terraform(ref, terraform_dir, run):
    """deploy.py's checks, then a plan that must change nothing. The plan
    refreshes from AWS, so a change made outside Terraform shows too."""
    deploy.check_variables(terraform_dir)
    deploy.check_code(terraform_dir.parent, ref, git=run)
    deploy.assemble(terraform_dir.parent)
    try:
        deploy.terraform(["plan", "-input=false", "-out", PLAN_FILE], terraform_dir, run, capture=True)
        summary = deploy.summarise(json.loads(
            deploy.terraform(["show", "-json", PLAN_FILE], terraform_dir, run, capture=True)))
    finally:
        (terraform_dir / PLAN_FILE).unlink(missing_ok=True)
    if not any(summary.values()):
        return []
    lines = []
    deploy.report(summary, out=lines.append)
    return [line.strip() for line in lines]


AGAINST_OUTPUTS = {"corpus": check_corpus, "scanner": check_scanner, "dashboard": check_dashboard}


# ---------- the run ----------

def terraform_outputs(terraform_dir, run):
    shown = deploy.terraform(["output", "-json"], terraform_dir, run, capture=True)
    return {name: output["value"] for name, output in json.loads(shown).items()}


def aws_clients(outputs):
    """Clients in the stack's region, read from its ECR repository's URL so
    it does not hang on whatever region the shell defaults to."""
    import boto3
    region = outputs["scanner_ecr_repository_url"].split(".")[3]
    return {name: boto3.client(name, region_name=region) for name in ("s3", "lambda", "ecr")}


def main(argv=None, run=subprocess.run, aws=None, out=print):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--terraform-dir", type=Path, default=REPO / "terraform",
                    help="the Terraform root holding the state (default: this repository's terraform/)")
    ap.add_argument("--ref", default="origin/main",
                    help="the git ref the deployed stack should match (default origin/main)")
    ap.add_argument("--skip", action="append", default=[], choices=CHECKS,
                    help="leave a check out; repeat for each")
    args = ap.parse_args(argv)
    terraform_dir = args.terraform_dir.resolve()

    run(["git", "-C", str(REPO), "fetch", "--quiet", "origin"], capture_output=True)
    try:
        outputs = terraform_outputs(terraform_dir, run)
        aws = aws or aws_clients(outputs)
    except Stop as e:
        print(f"drift: not checked. {e}", file=sys.stderr)
        return 1

    found = []
    for name in CHECKS:
        if name in args.skip:
            out(f"{name}: skipped")
            continue
        try:
            problems = (check_terraform(args.ref, terraform_dir, run) if name == "terraform"
                        else AGAINST_OUTPUTS[name](args.ref, outputs, aws, run))
        except Stop as e:
            problems = [f"not checked. {e}"]
        except Exception as e:
            # Expired credentials, say: one check that cannot run is reported
            # as such, and the others still run.
            problems = [f"not checked. {type(e).__name__}: {e}"]
        if problems:
            found.append(name)
            out(f"{name}: differs from {args.ref}")
            for problem in problems:
                out("  " + problem.replace("\n", "\n    "))
        else:
            out(f"{name}: matches {args.ref}")

    out(f"drift: {', '.join(found)}" if found else "drift: none")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
