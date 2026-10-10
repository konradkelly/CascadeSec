import io
import json
import tarfile

import pytest
from botocore.exceptions import ClientError

import cdk
import handler

PR = "gh-123-7"
PROJECT = f"projects/{PR}/abc123.tgz"


# --- fixtures -----------------------------------------------------------------

def tgz(members):
    """A gzipped tar of {name: bytes | TarInfo-type str}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            if data == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tar.addfile(info)
                continue
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def frame(where, fn="new Thing"):
    return f"{fn} (/work/src/{where})"


TEMPLATE = {
    "Resources": {
        "Data666C94C7": {"Type": "AWS::S3::Bucket", "UpdateReplacePolicy": "Retain"},
        "NetSsh9740AB70": {"Type": "AWS::EC2::SecurityGroup",
                           "Properties": {"SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0"}]}},
        "NetVpcSubnet1": {"Type": "AWS::EC2::Subnet", "Properties": {}},
        "CDKMetadata": {"Type": "AWS::CDK::Metadata"},
    },
    "Parameters": {"BootstrapVersion": {"Type": "AWS::SSM::Parameter::Value<String>"}},
}

METADATA = {
    "/ProbeStack": [{"type": "aws:cdk:creationStack", "data": [frame("infra/bin/app.ts:4:1", "<anonymous>")]}],
    "/ProbeStack/Data/Resource": [
        {"type": "aws:cdk:logicalId", "data": "Data666C94C7"},
        {"type": "aws:cdk:creationStack", "data": ["...new Bucket2 in aws-cdk-lib...",
                                                   frame("infra/lib/storage.ts:6:10", "addStorage")]},
    ],
    "/ProbeStack/Net/Ssh/Resource": [
        {"type": "aws:cdk:logicalId", "data": "NetSsh9740AB70"},
        {"type": "aws:cdk:creationStack", "data": [frame("infra/lib/network.ts:8:16")]},
        {"type": "aws:cdk:propertyAssignment", "data": {
            "propertyName": "SecurityGroupIngress",
            "stackTrace": ["...in aws-cdk-lib...", frame("infra/lib/network.ts:9:8")]}},
    ],
    # A library construct's child: no user frame of its own.
    "/ProbeStack/Net/Vpc": [{"type": "aws:cdk:creationStack", "data": [frame("infra/lib/network.ts:7:17")]}],
    "/ProbeStack/Net/Vpc/Subnet1/Subnet": [
        {"type": "aws:cdk:logicalId", "data": "NetVpcSubnet1"},
        {"type": "aws:cdk:creationStack", "data": [".../work/src/infra/node_modules/aws-cdk-lib/vpc.js:1:2 in aws-cdk-lib..."]},
    ],
}


def assembly(template=TEMPLATE, metadata=METADATA, manifest=None, extra=None):
    manifest = manifest if manifest is not None else {"version": "54.0.0", "artifacts": {
        "ProbeStack": {"type": "aws:cloudformation:stack", "displayName": "ProbeStack",
                       "properties": {"templateFile": "ProbeStack.template.json"},
                       "additionalMetadataFile": "ProbeStack.metadata.json"},
        "Tree": {"type": "cdk:tree", "properties": {"file": "tree.json"}},
    }}
    return {"manifest.json": json.dumps(manifest).encode(),
            "ProbeStack.template.json": json.dumps(template).encode(),
            "ProbeStack.metadata.json": json.dumps(metadata).encode(),
            **(extra or {})}


class FakeS3:
    def __init__(self):
        self.objects = {}  # (bucket, key) -> bytes
        self.copies = []

    def put_object(self, Bucket, Key, Body, ContentType):
        assert (Bucket, Key.split("/")[0]) in {("sb", "runs"), ("art", "scans")}
        self.objects[(Bucket, Key)] = Body

    def copy_object(self, Bucket, Key, CopySource):
        self.copies.append((CopySource["Bucket"], CopySource["Key"], Bucket, Key))

    def generate_presigned_url(self, op, Params, ExpiresIn):
        return f"https://{Params['Bucket']}.s3.test/{Params['Key']}?op={op}&X-Amz-Signature=sig"

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ContentLength": len(self.objects[(Bucket, Key)])}

    def get_object(self, Bucket, Key, Range):
        end = int(Range.split("-")[1])
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)][: end + 1])}


class FakeCodeArtifact:
    def get_repository_endpoint(self, **kw):
        return {"repositoryEndpoint": "https://dom-123.d.codeartifact.us-east-1.amazonaws.com/npm/npm-mirror/"}

    def get_authorization_token(self, **kw):
        return {"authorizationToken": "ca-token"}


@pytest.fixture(autouse=True)
def s3(monkeypatch):
    fake = FakeS3()
    monkeypatch.setattr(handler, "s3", fake)
    monkeypatch.setattr(handler, "codeartifact", FakeCodeArtifact())
    monkeypatch.setattr(handler, "_npm_endpoint", None)
    monkeypatch.setattr(handler, "SANDBOX_BUCKET", "sb")
    monkeypatch.setattr(handler, "ARTIFACTS_BUCKET", "art")
    monkeypatch.setattr(handler, "SANDBOX_ACTIVE", True)
    return fake


def synth_request(**over):
    return {"kind": "cdk-synth", "phases": ["fetch", "execute"], "timeout_seconds": 600,
            "pr_id": PR, "app_dir": "infra", "project_key": PROJECT, **over}


def manifest_of(s3, prepared, phase):
    run_id = prepared["prepared"]["run_id"]
    return json.loads(s3.objects[("sb", f"runs/{run_id}/{phase}/manifest.json")])


# --- cdk.py: the archive ---------------------------------------------------------

def test_only_the_assemblys_own_files_are_read():
    files = cdk.read_archive(io.BytesIO(tgz({
        **assembly(),
        "tree.json": b"{}",
        "asset.abc/index.js": b"x",
        "../escape.template.json": b"{}",
        "/abs.template.json": b"{}",
        "link.template.json": "symlink",
        "assembly-Prod/manifest.json": b"{}",
        "assembly-Prod/deep/x.template.json": b"{}",
    })))
    assert sorted(files) == ["ProbeStack.metadata.json", "ProbeStack.template.json",
                             "assembly-Prod/manifest.json", "manifest.json"]


@pytest.mark.parametrize("data,why", [
    (b"not gzip", "not a readable archive"),
    (tgz({f"x{i}.json": b"" for i in range(cdk.MAX_MEMBERS + 1)}), "more than"),
])
def test_an_unreadable_or_oversized_archive_is_hostile(data, why):
    with pytest.raises(cdk.Hostile, match=why):
        cdk.read_archive(io.BytesIO(data))


def test_a_file_over_its_cap_is_refused(monkeypatch):
    monkeypatch.setattr(cdk, "MAX_FILE_BYTES", 10)
    with pytest.raises(cdk.Hostile, match="over"):
        cdk.read_archive(io.BytesIO(tgz({"manifest.json": b"x" * 11})))


def test_the_total_is_capped_too(monkeypatch):
    monkeypatch.setattr(cdk, "MAX_UNPACKED_BYTES", 15)
    with pytest.raises(cdk.Hostile, match="unpacked"):
        cdk.read_archive(io.BytesIO(tgz({"manifest.json": b"x" * 10, "a.template.json": b"y" * 10})))


# --- cdk.py: the assembly --------------------------------------------------------

def test_stacks_are_found_with_their_template_and_metadata():
    [(path, name, template, metadata)] = cdk.stacks(assembly())
    assert (path, name) == ("ProbeStack", "ProbeStack")
    assert template == TEMPLATE and metadata == METADATA


def test_metadata_inline_in_the_manifest_is_read_too():
    manifest = {"artifacts": {"Old": {"type": "aws:cloudformation:stack",
                                      "properties": {"templateFile": "ProbeStack.template.json"},
                                      "metadata": METADATA}}}
    [(_, _, _, metadata)] = cdk.stacks(assembly(manifest=manifest))
    assert metadata == METADATA


def test_a_stage_is_followed_one_level():
    nested = {"artifacts": {"ProdApi": {"type": "aws:cloudformation:stack",
                                        "properties": {"templateFile": "ProdApi.template.json"}}}}
    files = {"manifest.json": json.dumps({"artifacts": {"assembly-Prod": {
                 "type": "cdk:cloud-assembly", "properties": {"directoryName": "assembly-Prod"}}}}).encode(),
             "assembly-Prod/manifest.json": json.dumps(nested).encode(),
             "assembly-Prod/ProdApi.template.json": json.dumps(TEMPLATE).encode()}
    assert [s[0] for s in cdk.stacks(files)] == ["assembly-Prod/ProdApi"]


@pytest.mark.parametrize("manifest,why", [
    ({"artifacts": {"../../x": {"type": "aws:cloudformation:stack",
                                "properties": {"templateFile": "ProbeStack.template.json"}}}}, "unexpected shape"),
    ({"artifacts": {"S": {"type": "aws:cloudformation:stack",
                          "properties": {"templateFile": "../other.template.json"}}}}, "names no template"),
    ({"artifacts": {"n": {"type": "cdk:cloud-assembly",
                          "properties": {"directoryName": "../up"}}}}, "unexpected name"),
    ({"artifacts": []}, "has no artifacts"),
    ([], "has no artifacts"),
])
def test_a_manifest_naming_anything_odd_is_hostile(manifest, why):
    with pytest.raises(cdk.Hostile, match=why):
        cdk.stacks(assembly(manifest=manifest))


def test_a_template_that_is_not_one_is_hostile():
    with pytest.raises(cdk.Hostile, match="not a template"):
        cdk.stacks(assembly(template=["not", "a", "template"]))
    with pytest.raises(cdk.Hostile, match="not UTF-8 JSON"):
        cdk.stacks({**assembly(), "ProbeStack.template.json": b"\xff{"})


# --- cdk.py: the source map --------------------------------------------------------

def test_each_resource_maps_to_the_line_that_made_it():
    resources, site = cdk.source_map(METADATA)
    assert site == {"file": "infra/bin/app.ts", "line": 4}
    assert resources["Data666C94C7"]["file"] == "infra/lib/storage.ts"
    assert resources["Data666C94C7"]["line"] == 6
    assert resources["NetSsh9740AB70"]["path"] == "/ProbeStack/Net/Ssh/Resource"
    # The line that set the property, which is where a fix would go.
    assert resources["NetSsh9740AB70"]["assignments"] == [
        {"property": "SecurityGroupIngress", "file": "infra/lib/network.ts", "line": 9}]


def test_a_library_made_resource_takes_its_nearest_ancestors_line():
    resources, _ = cdk.source_map(METADATA)
    # Its own frame is under node_modules, which is never the project's.
    assert (resources["NetVpcSubnet1"]["file"], resources["NetVpcSubnet1"]["line"]) == ("infra/lib/network.ts", 7)


@pytest.mark.parametrize("trace", [
    ["new X (/etc/passwd:1:1)"],
    ["new X (/work/src/../../etc/passwd:1:1)"],
    ["new X (/work/src/a/./b.ts:1:1)"],
    ["new X (/work/src/a//b.ts:1:1)"],
    ["new X (/work/src/node_modules/x/y.js:1:1)"],
    ["new X (/work/src/a\\b.ts:1:1)"],
    ["new X (/work/src/a.ts:0:1)"],
    [{"not": "a string"}],
    "not a list",
])
def test_only_project_frames_count(trace):
    assert cdk._user_frame(trace) is None


def test_a_bare_frame_without_a_function_counts():
    assert cdk._user_frame(["/work/src/bin/app.ts:4:1"]) == {"file": "bin/app.ts", "line": 4}


def test_hostile_logical_ids_are_never_mapped():
    resources, _ = cdk.source_map({"/S/X": [{"type": "aws:cdk:logicalId", "data": "../x"}]})
    assert resources == {}


# --- cdk.py: rendering and the whole build ------------------------------------------

def test_spans_cover_each_resource_in_the_rewritten_text():
    text, spans = cdk.render(TEMPLATE)
    lines = text.split("\n")
    assert set(spans) == set(TEMPLATE["Resources"])
    for logical_id, (start, end) in spans.items():
        assert lines[start - 1].startswith(f'  "{logical_id}": {{')
        assert lines[end - 1].strip() in ("}", "},", f'"{logical_id}": {{}}', f'"{logical_id}": {{}},') or start == end
        body = json.loads("{" + "\n".join(lines[start - 1:end]).rstrip(",") + "}")
        assert body[logical_id] == TEMPLATE["Resources"][logical_id]
    # Parameters are not resources, even with a Type.
    assert "BootstrapVersion" not in spans


def test_an_empty_resource_is_one_line():
    _, spans = cdk.render({"Resources": {"A": {}, "B": {"Type": "AWS::S3::Bucket"}}})
    assert spans["A"][0] == spans["A"][1]


def test_build_writes_a_template_and_its_source_map_under_the_app():
    outputs, summary = cdk.build(assembly(), "infra")
    assert sorted(outputs) == ["infra/cdk.out/ProbeStack.template.json", "infra/cdk.out/ProbeStack.template.sources"]
    assert json.loads(outputs["infra/cdk.out/ProbeStack.template.json"]) == TEMPLATE
    sources = json.loads(outputs["infra/cdk.out/ProbeStack.template.sources"])
    assert sources["site"] == {"file": "infra/bin/app.ts", "line": 4}
    ssh = sources["resources"]["NetSsh9740AB70"]
    assert ssh["type"] == "AWS::EC2::SecurityGroup" and ssh["file"] == "infra/lib/network.ts"
    # The resource with no metadata at all (CDK's own) is spanned but not located.
    assert sources["resources"]["CDKMetadata"]["file"] is None
    assert summary == [{"stack": "ProbeStack", "template": "infra/cdk.out/ProbeStack.template.json",
                        "resources": 4, "unlocated": 1}]


def test_a_root_app_writes_under_cdk_out():
    outputs, _ = cdk.build(assembly(), ".")
    assert "cdk.out/ProbeStack.template.json" in outputs


def test_missing_context_names_the_providers():
    manifest = {"artifacts": {}, "missing": [{"provider": "vpc-provider", "key": "k"},
                                             {"provider": "availability-zones"}, "junk"]}
    assert cdk.missing_context({"manifest.json": json.dumps(manifest).encode()}) == [
        "availability-zones", "vpc-provider"]


# --- handler: prepare ---------------------------------------------------------------

def test_prepare_copies_the_project_into_the_sandbox_bucket(s3):
    out = handler.prepare(synth_request())
    run_id = out["prepared"]["run_id"]
    assert s3.copies == [("art", PROJECT, "sb", f"runs/{run_id}/input/project.tgz")]
    assert out["prepared"]["pr_id"] == PR and out["prepared"]["app_dir"] == "infra"
    fetch, execute = manifest_of(s3, out, "fetch"), manifest_of(s3, out, "execute")
    for m in (fetch, execute):
        assert m["APP_DIR"] == "infra"
        assert f"runs/{run_id}/input/project.tgz?op=get_object" in m["SNAPSHOT_URL"]
        assert m["STEP_TIMEOUT_SECONDS"] == 600 - handler.STEP_TIMEOUT_MARGIN_SECONDS
    # Execute reads what fetch wrote, and writes only its own.
    assert f"runs/{run_id}/fetch/output.tgz?op=get_object" in execute["DEPS_URL"]
    assert f"runs/{run_id}/execute/output.tgz?op=put_object" in execute["OUTPUT_URL"]
    assert "DEPS_URL" not in fetch and "CODEARTIFACT_TOKEN" not in execute


@pytest.mark.parametrize("over", [
    {"pr_id": "../x"}, {"pr_id": None},
    {"app_dir": "../infra"}, {"app_dir": "/infra"}, {"app_dir": "a/node_modules/b"}, {"app_dir": ""},
    {"project_key": "scans/gh-123-7/x.tgz"}, {"project_key": "projects/gh-999-1/x.tgz"},
    {"project_key": f"projects/{PR}/../../secrets.tgz"}, {"project_key": f"projects/{PR}/x.zip"},
    {"phases": ["execute"]},
])
def test_prepare_refuses_a_synth_it_cannot_trust(over):
    with pytest.raises(handler.BadRequest):
        handler.prepare(synth_request(**over))


def test_a_switched_off_sandbox_starts_nothing(s3, monkeypatch):
    monkeypatch.setattr(handler, "SANDBOX_ACTIVE", False)
    out = handler.prepare(synth_request())
    p = out["prepared"]
    assert p["unavailable"] and not p["run_fetch"] and not p["run_execute"]
    assert s3.copies == [] and s3.objects == {}
    synth = handler.collect({"run_id": p["run_id"], "kind": "cdk-synth", "phases": p["phases"],
                             "pr_id": PR, "app_dir": "infra", "unavailable": True})["synth"]
    assert synth["status"] == "unavailable" and synth["templates"] == []


# --- handler: collect ------------------------------------------------------------------

RUN = "a" * 32


def put_result(s3, phase, **result):
    s3.objects[("sb", f"runs/{RUN}/{phase}/result.json")] = json.dumps(
        {"phase": phase, "kind": "cdk-synth", **result}).encode()


def collect(**over):
    return handler.collect({"run_id": RUN, "kind": "cdk-synth", "phases": ["fetch", "execute"],
                            "pr_id": PR, "app_dir": "infra", "unavailable": False,
                            "tasks": {}, "errors": {}, **over})


def test_a_successful_synth_lands_in_the_scan_prefix(s3):
    put_result(s3, "fetch", status="ok", exit_code=0, duration_ms=40000, log_tail="added 10 packages")
    put_result(s3, "execute", status="ok", exit_code=0, duration_ms=12000, log_tail="")
    s3.objects[("sb", f"runs/{RUN}/execute/output.tgz")] = tgz(assembly())
    synth = collect()["synth"]
    assert synth["status"] == "ok"
    assert synth["templates"] == ["infra/cdk.out/ProbeStack.template.json"]
    assert ("art", f"scans/{PR}/infra/cdk.out/ProbeStack.template.json") in s3.objects
    assert ("art", f"scans/{PR}/infra/cdk.out/ProbeStack.template.sources") in s3.objects


def test_an_install_failure_is_reported_as_the_install_stage(s3):
    put_result(s3, "fetch", status="unsupported", reason="no package-lock.json in infra")
    put_result(s3, "execute", status="error", reason="download: http:404")
    synth = collect()["synth"]
    assert (synth["status"], synth["stage"]) == ("unsupported", "install")
    assert "package-lock.json" in synth["reason"]
    assert not any(b == "art" for b, _ in s3.objects)


def test_a_synth_failure_carries_its_reason_not_its_log(s3):
    put_result(s3, "fetch", status="ok")
    put_result(s3, "execute", status="failed", reason="the app exited 1", log_tail="<script>x</script>" * 1000)
    out = collect()
    assert (out["synth"]["status"], out["synth"]["reason"]) == ("failed", "the app exited 1")
    # The log stays in the run's own record, clipped, and out of the summary.
    assert "log_tail" not in out["synth"]
    assert len(out["phases"]["execute"]["result"]["log_tail"]) <= handler.MAX_LOG_TAIL


def test_a_task_that_never_ran_is_an_error_with_why(s3):
    out = collect(errors={"fetch": {"Error": "States.TaskFailed", "Cause": json.dumps(
        {"StopCode": "TaskFailedToStart", "StoppedReason": "CannotPullContainerError"})}})
    assert out["synth"]["status"] == "error" and "CannotPullContainerError" in out["synth"]["reason"]


@pytest.mark.parametrize("result", [{"status": "great"}, {"status": None}, {}])
def test_an_unknown_status_is_malformed(s3, result):
    put_result(s3, "fetch", **result)
    assert collect()["synth"]["status"] == "error"


def test_success_without_an_assembly_is_an_error(s3):
    put_result(s3, "fetch", status="ok")
    put_result(s3, "execute", status="ok")
    assert collect()["synth"]["reason"] == "the synth reported success and uploaded nothing"


def test_a_hostile_assembly_is_rejected_and_nothing_written(s3):
    put_result(s3, "fetch", status="ok")
    put_result(s3, "execute", status="ok")
    s3.objects[("sb", f"runs/{RUN}/execute/output.tgz")] = tgz(assembly(manifest={"artifacts": {
        "../../x": {"type": "aws:cloudformation:stack", "properties": {"templateFile": "ProbeStack.template.json"}}}}))
    synth = collect()["synth"]
    assert synth["status"] == "rejected"
    assert not any(b == "art" for b, _ in s3.objects)


def test_an_oversized_assembly_is_never_read(s3, monkeypatch):
    monkeypatch.setattr(cdk, "MAX_ARCHIVE_BYTES", 10)
    put_result(s3, "fetch", status="ok")
    put_result(s3, "execute", status="ok")
    s3.objects[("sb", f"runs/{RUN}/execute/output.tgz")] = tgz(assembly())
    assert collect()["synth"]["status"] == "rejected"


def test_lookups_without_cached_context_are_reported_not_scanned(s3):
    put_result(s3, "fetch", status="ok")
    put_result(s3, "execute", status="ok")
    files = assembly()
    manifest = json.loads(files["manifest.json"])
    manifest["missing"] = [{"provider": "vpc-provider"}]
    files["manifest.json"] = json.dumps(manifest).encode()
    s3.objects[("sb", f"runs/{RUN}/execute/output.tgz")] = tgz(files)
    synth = collect()["synth"]
    assert synth["status"] == "needs-context" and "vpc-provider" in synth["reason"]
    assert not any(b == "art" for b, _ in s3.objects)


@pytest.mark.parametrize("over", [{"pr_id": "../x"}, {"app_dir": "../x"}, {"pr_id": None}])
def test_collect_refuses_a_synth_prepare_would_not_have_made(over):
    with pytest.raises(handler.BadRequest):
        collect(**over)


def test_prepare_takes_the_executions_input_as_request(s3):
    out = handler.handler({"action": "prepare", "request": synth_request()}, None)
    assert out["prepared"]["app_dir"] == "infra"
    # The containment's own kinds still carry the fields Collect's paths name.
    leak = handler.handler({"action": "prepare", "request": {
        "kind": "leak-test", "phases": ["fetch", "execute"], "timeout_seconds": 300}}, None)["prepared"]
    assert (leak["pr_id"], leak["app_dir"], leak["unavailable"]) == (None, None, False)
