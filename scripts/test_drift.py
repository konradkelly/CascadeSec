"""The drift check. No terraform, npm or AWS: `run` answers git, terraform
and npm from canned data, and the AWS clients are fakes holding objects
and images.

The case that earns the file is 2026-10-11's: a corpus file in S3 older
than the repository's must be named, not passed because the listing has
the right keys."""

import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import deploy  # noqa: E402
import drift  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
RUNNING = "sha256:" + "a" * 64
NEWER = "sha256:" + "b" * 64
OUTPUTS = {
    "artifacts_bucket_name": "artifacts",
    "dashboard_bucket_name": "dashboard",
    "iac_scanner_function_name": "iacposture-dev-iac-scanner",
    "scanner_ecr_repository_url": "123.dkr.ecr.us-east-1.amazonaws.com/iacposture-dev-iac-scanner",
    "review_api_endpoint": "https://api.example.test/",
    "cognito_hosted_ui_domain": "auth.example.test",
    "cognito_dashboard_client_id": "client",
}
CORPUS = {"corpus/frameworks/cis-aws-1.4.json": b'{"id": "cis-aws"}\n',
          "corpus/rule_mappings.json": b'{"trivy": {}}\n'}
PIN = f'SCANNER_IMAGE = ("ghcr.io/konradkelly/cascadesec-scanner"\n                 "@{RUNNING}")\n'.encode()
DIST = {"index.html": b"<html></html>\n", "assets/index-abc.js": b"console.log(1)\n"}


@pytest.fixture(autouse=True)
def npm_on_path(monkeypatch):
    """FakeRun answers npm, so the machine running these needs none."""
    monkeypatch.setattr(drift.shutil, "which", lambda name: f"/usr/bin/{name}")


def etag(data):
    return f'"{hashlib.md5(data).hexdigest()}"'


class FakeS3:
    """Buckets of {key: bytes}, listed a page of `page` keys at a time."""

    def __init__(self, buckets, page=1000):
        self.buckets, self.page, self.reads = buckets, page, []

    def list_objects_v2(self, Bucket, Prefix="", ContinuationToken=None):
        keys = sorted(k for k in self.buckets[Bucket] if k.startswith(Prefix))
        start = int(ContinuationToken or 0)
        page = {"Contents": [{"Key": k, "ETag": etag(self.buckets[Bucket][k])}
                             for k in keys[start:start + self.page]]}
        if start + self.page < len(keys):
            page["NextContinuationToken"] = str(start + self.page)
        return page

    def get_object(self, Bucket, Key):
        self.reads.append(Key)
        return {"Body": io.BytesIO(self.buckets[Bucket][Key])}


class FakeLambda:
    def __init__(self, digest):
        self.digest = digest

    def get_function(self, FunctionName):
        uri = f"{OUTPUTS['scanner_ecr_repository_url']}@{self.digest}"
        return {"Code": {"RepositoryType": "ECR", "ImageUri": uri, "ResolvedImageUri": uri}}


class FakeECR:
    """{digest: tags}; `latest` is whichever digest carries it."""

    class exceptions:
        class ImageNotFoundException(Exception):
            pass

    def __init__(self, images):
        self.images = images

    def describe_images(self, repositoryName, imageIds):
        wanted = imageIds[0]
        for digest, tags in self.images.items():
            if wanted.get("imageDigest") == digest or wanted.get("imageTag") in tags:
                return {"imageDetails": [{"imageDigest": digest, "imageTags": tags}]}
        raise self.exceptions.ImageNotFoundException(str(wanted))


def tar_of(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FakeRun:
    """git from {path: bytes} at the ref and a list of paths changed since
    each commit; terraform from canned outputs and a plan; npm by writing
    `dist` where the build runs."""

    def __init__(self, files=None, changed=None, plan=None, dist=None, npm_ok=True):
        self.files = {**CORPUS, drift.SCANNER_PIN: PIN, "dashboard/package.json": b"{}\n", **(files or {})}
        self.changed = {"b85206d": []} if changed is None else changed
        self.plan = plan or {"resource_changes": []}
        self.dist, self.npm_ok = DIST if dist is None else dist, npm_ok
        self.calls = []

    def __call__(self, cmd, capture_output=False, text=False, cwd=None):
        self.calls.append(cmd)
        done = lambda out, code=0, err="": subprocess.CompletedProcess(cmd, code, out, err)  # noqa: E731
        if cmd[0] == "git":
            verb = cmd[3]
            if verb == "ls-tree":
                paths = cmd[cmd.index("--") + 1:]
                listed = [p for p in self.files if any(p == q or p.startswith(q + "/") for q in paths)]
                return done("\n".join(sorted(listed)).encode())
            if verb == "show":
                path = cmd[-1].split(":", 1)[1]
                return done(self.files[path]) if path in self.files else done(b"", 128)
            if verb == "diff":
                commit = cmd[cmd.index("--name-only") + 1]
                if commit not in self.changed:
                    return done(b"", 128)
                return done("\n".join(self.changed[commit]).encode())
            if verb == "archive":
                return done(tar_of({p: d for p, d in self.files.items() if p.startswith("dashboard/")}))
            return done(b"")
        if cmd[0] == "terraform":
            verb = cmd[2]
            if verb == "output":
                return done(json.dumps({k: {"value": v, "sensitive": False} for k, v in OUTPUTS.items()}))
            if verb == "plan":
                Path(cmd[1].removeprefix("-chdir="), drift.PLAN_FILE).write_text("binary plan")
                return done("")
            if verb == "show":
                return done(json.dumps(self.plan))
        if Path(cmd[0]).stem.lower() == "npm":
            if not self.npm_ok:
                return done("", 1, "npm ERR! missing script: build")
            if cmd[1:] == ["run", "build"]:
                self.env = (Path(cwd) / ".env").read_text()
                for path, data in self.dist.items():
                    (Path(cwd) / "dist" / path).parent.mkdir(parents=True, exist_ok=True)
                    (Path(cwd) / "dist" / path).write_bytes(data)
            return done("")
        raise AssertionError(f"unexpected command {cmd}")


def aws(corpus=None, dashboard=None, images=None, running=RUNNING):
    return {"s3": FakeS3({"artifacts": dict(CORPUS if corpus is None else corpus),
                          "dashboard": dict(DIST if dashboard is None else dashboard)}),
            "lambda": FakeLambda(running),
            "ecr": FakeECR({RUNNING: ["latest", "b85206d"]} if images is None else images)}


# ---------- corpus ----------

def test_a_corpus_that_matches_is_clean_and_read_only_where_an_etag_differs():
    clients = aws()
    assert drift.check_corpus("origin/main", OUTPUTS, clients, FakeRun()) == []
    assert clients["s3"].reads == []


def test_a_corpus_file_older_than_the_repository_is_named():
    """2026-10-11: the keys were all there, and one of them was stale."""
    stale = {**CORPUS, "corpus/rule_mappings.json": b'{"tfsec": {}}\n'}
    problems = drift.check_corpus("origin/main", OUTPUTS, aws(corpus=stale), FakeRun())
    assert problems == ["differs: corpus/rule_mappings.json"]


def test_a_corpus_uploaded_with_crlf_is_not_drift():
    crlf = {k: v.replace(b"\n", b"\r\n") for k, v in CORPUS.items()}
    clients = aws(corpus=crlf)
    assert drift.check_corpus("origin/main", OUTPUTS, clients, FakeRun()) == []
    assert sorted(clients["s3"].reads) == sorted(CORPUS)


def test_a_missing_file_and_one_the_repository_no_longer_has_are_both_named():
    deployed = {"corpus/rule_mappings.json": CORPUS["corpus/rule_mappings.json"],
                "corpus/frameworks/retired.json": b"{}"}
    problems = drift.check_corpus("origin/main", OUTPUTS, aws(corpus=deployed), FakeRun())
    assert problems == ["not deployed: corpus/frameworks/cis-aws-1.4.json",
                        "deployed, not in the repository: corpus/frameworks/retired.json"]


def test_every_page_of_a_listing_is_read():
    s3 = FakeS3({"b": {f"k{i}": b"x" for i in range(5)}}, page=2)
    assert sorted(drift.list_bucket(s3, "b")) == [f"k{i}" for i in range(5)]


# ---------- scanner ----------

def test_a_scanner_that_is_latest_pinned_and_built_from_the_ref_is_clean():
    assert drift.check_scanner("origin/main", OUTPUTS, aws(), FakeRun()) == []


def test_an_image_pushed_but_not_applied_is_named():
    images = {RUNNING: ["b85206d"], NEWER: ["latest", "c0ffee1"]}
    problems = drift.check_scanner("origin/main", OUTPUTS, aws(images=images), FakeRun())
    assert problems == [f"the Lambda runs {RUNNING}, and ECR's latest is {NEWER}: the next apply rolls it"]


def test_a_cli_pinned_to_another_image_is_named():
    pin = PIN.replace(RUNNING.encode(), NEWER.encode())
    problems = drift.check_scanner("origin/main", OUTPUTS, aws(), FakeRun(files={drift.SCANNER_PIN: pin}))
    assert problems == [f"the CLI pins {NEWER} ({drift.SCANNER_PIN}), and the Lambda runs {RUNNING}"]


def test_a_scanner_input_changed_since_the_images_commit_is_named():
    run = FakeRun(changed={"b85206d": ["lambda/iac-scanner/local_main.py"]})
    problems = drift.check_scanner("origin/main", OUTPUTS, aws(), run)
    assert problems == ["the image was built from b85206d, and on origin/main since then: "
                        "lambda/iac-scanner/local_main.py"]
    diff = next(c for c in run.calls if c[0] == "git" and c[3] == "diff")
    assert diff[diff.index("--") + 1:] == list(drift.SCANNER_INPUTS)


def test_an_image_with_no_commit_tag_or_gone_from_ecr_is_unknown_not_clean():
    untagged = drift.check_scanner("origin/main", OUTPUTS, aws(images={RUNNING: ["latest"]}), FakeRun())
    assert untagged == [f"{RUNNING} carries no commit tag, so what it was built from is unknown"]

    gone = drift.check_scanner("origin/main", OUTPUTS, aws(images={NEWER: ["latest"]}), FakeRun())
    assert f"ECR no longer holds {RUNNING}, so what it was built from is unknown" in gone


# ---------- dashboard ----------

def test_the_dashboard_is_built_from_the_ref_with_the_stacks_values():
    run = FakeRun()
    assert drift.check_dashboard("origin/main", OUTPUTS, aws(), run) == []
    assert ["git", "-C", str(REPO), "archive", "--format=tar", "origin/main", "dashboard"] in run.calls
    # .env.example: no trailing slash on the API's base URL.
    assert "VITE_API_BASE_URL=https://api.example.test\n" in run.env
    assert "VITE_COGNITO_CLIENT_ID=client\n" in run.env


def test_a_dashboard_deployed_from_an_older_build_is_named():
    older = {"index.html": b"<html>old</html>\n", "assets/index-old.js": b"console.log(0)\n"}
    problems = drift.check_dashboard("origin/main", OUTPUTS, aws(dashboard=older), FakeRun())
    assert problems == ["not deployed: assets/index-abc.js", "differs: index.html",
                        "deployed, not in the repository: assets/index-old.js"]


def test_a_failed_build_stops_the_check():
    with pytest.raises(drift.Stop) as e:
        drift.check_dashboard("origin/main", OUTPUTS, aws(), FakeRun(npm_ok=False))
    assert "npm ci" in str(e.value)


# ---------- terraform ----------

@pytest.fixture
def root(tmp_path, monkeypatch):
    """A Terraform root deploy.py's checks pass on, and a REPO to match."""
    (tmp_path / "terraform").mkdir()
    (tmp_path / "terraform" / "terraform.tfvars").write_text(
        'github_app_id = "1"\nalarm_email = "k@example.test"\ngithub_writer_app_id = "2"\n')
    (tmp_path / "terraform" / "deploy.tfplan").write_text("the plan someone is reading")
    monkeypatch.setattr(deploy, "packaged_paths", lambda repo: [])
    monkeypatch.setattr(deploy, "VENDORED_CORE", ())
    return tmp_path / "terraform"


def test_a_plan_with_no_changes_is_clean_and_leaves_the_deploy_plan_alone(root):
    assert drift.check_terraform("origin/main", root, FakeRun()) == []
    assert not (root / drift.PLAN_FILE).exists()
    assert (root / "deploy.tfplan").read_text() == "the plan someone is reading"


def test_every_change_in_the_plan_is_listed(root):
    plan = {"resource_changes": [
        {"address": "aws_lambda_function.mapping_agent", "change": {"actions": ["update"]}},
        {"address": "aws_iam_role_policy.pipeline", "change": {"actions": ["update"]}},
        {"address": "data.aws_iam_policy_document.pipeline", "change": {"actions": ["read"]}},
    ]}
    problems = drift.check_terraform("origin/main", root, FakeRun(plan=plan))
    assert problems == ["plan: 0 creates, 2 updates, 0 replaces, 0 destroys",
                        "~ aws_lambda_function.mapping_agent", "~ aws_iam_role_policy.pipeline"]


def test_a_tfvars_missing_a_gating_variable_stops_before_planning(root):
    """Its plan would show write-back destroyed, which is not drift."""
    (root / "terraform.tfvars").write_text('github_app_id = "1"\nalarm_email = "k@x"\n')
    run = FakeRun()
    with pytest.raises(drift.Stop):
        drift.check_terraform("origin/main", root, run)
    assert not [c for c in run.calls if c[0] == "terraform"]


# ---------- the run ----------

def run_main(root, *args, clients=None, **fake):
    lines = []
    code = drift.main(["--terraform-dir", str(root), *args], run=FakeRun(**fake), aws=clients or aws(),
                      out=lines.append)
    return code, "\n".join(lines)


def test_a_stack_that_matches_everywhere_exits_zero(root):
    code, out = run_main(root)
    assert code == 0
    assert out.splitlines() == [f"{name}: matches origin/main" for name in drift.CHECKS] + ["drift: none"]


def test_any_drift_exits_one_and_every_check_still_runs(root):
    code, out = run_main(root, changed={"b85206d": ["lambda/iac-scanner/handler.py"]})
    assert code == 1
    assert "scanner: differs from origin/main" in out
    assert "terraform: matches origin/main" in out
    assert out.splitlines()[-1] == "drift: scanner"


def test_a_check_that_cannot_run_is_reported_and_the_others_run(root):
    class Expired(FakeS3):
        def list_objects_v2(self, **kwargs):
            raise RuntimeError("ExpiredToken")
    clients = {**aws(), "s3": Expired({})}
    code, out = run_main(root, clients=clients)
    assert code == 1
    assert "corpus: differs from origin/main\n  not checked. RuntimeError: ExpiredToken" in out
    assert "scanner: matches origin/main" in out


def test_a_skipped_check_says_so(root):
    code, out = run_main(root, "--skip", "dashboard")
    assert code == 0
    assert "dashboard: skipped" in out


# ---------- what the checks compare against ----------

def test_the_scanner_inputs_are_what_the_dockerfile_copies():
    """An image input the check does not compare could change on main
    while the check calls the deployed image current."""
    copies = set()
    dockerfile = (REPO / "lambda/iac-scanner/Dockerfile").read_text(encoding="utf-8")
    for stage, source in re.findall(r"^COPY\s+(?:--from=(\S+)\s+)?(\S+)\s+\S+$", dockerfile, re.M):
        if not stage:
            copies.add(f"lambda/iac-scanner/{source.rstrip('/')}")
        elif stage == "corpus":                       # build-image.sh's --build-context
            copies.add(f"corpus/{source.rstrip('/')}")
        # Any other stage is an image the Dockerfile itself pins.
    assert set(drift.SCANNER_INPUTS) == copies | {"lambda/iac-scanner/Dockerfile"}


def test_the_corpus_is_what_upload_sh_uploads():
    script = (REPO / "corpus/upload.sh").read_text(encoding="utf-8")
    uploaded = re.findall(r'^aws s3 (?:sync|cp) "\$\{SCRIPT_DIR\}/([^"]+)"', script, re.M)
    assert sorted(f"corpus/{p}" for p in uploaded) == sorted(drift.CORPUS)
