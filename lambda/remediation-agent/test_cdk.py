"""remediation-agent's CDK path (docs/sandbox-spec.md §9 step 3).

The handler drafts one resource's fix, yields a re-synth to the state
machine, and resumes with its result. These tests play the state machine:
each call's output is the next call's input, with `sandbox_result` added
where the sandbox would have run.
"""

import io
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

import handler

PR = "gh-1-4"
SOURCE = "infra/lib/storage.ts"
TEMPLATE = "infra/cdk.out/ProbeStack.template.json"
RUN = "a" * 32
PROJECT = f"projects/{PR}/sha.tgz"
DATA, LOGS = "/ProbeStack/Data/Resource", "/ProbeStack/Logs/Resource"
B1, B2, K1, S1 = "b1b1b1b1b1b1b1b1", "b2b2b2b2b2b2b2b2", "k1k1k1k1k1k1k1k1", "s1s1s1s1s1s1s1s1"

ORIGINAL = "export function addStorage(scope) {\n  new s3.Bucket(scope, 'Data');\n  new s3.Bucket(scope, 'Logs');\n}\n"


def finding(fid, rule, path, line, severity="HIGH", source="trivy", file=SOURCE, logical_id="X"):
    return {"pk": f"PR#{PR}", "sk": f"FINDING#{fid}", "finding_id": fid, "status": "mapped",
            "target_type": "cdk", "source": source, "rule_id": rule, "severity": severity,
            "file": TEMPLATE, "resource": path or "", "title": f"title of {rule}",
            "line_range": [3, 7],
            "origin": {"app": "infra", "file": file, "line": line, "construct_path": path,
                       "logical_id": logical_id, "type": "AWS::S3::Bucket", "assignments": []}}


class FakeTable:
    def __init__(self, items):
        self.items = {i["sk"]: i for i in items}
        self.updates = []

    def query(self, **kw):
        return {"Items": [dict(i) for i in self.items.values()]}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, **kw):
        self.updates.append((Key["sk"], ExpressionAttributeValues))
        item = self.items[Key["sk"]]
        values = ExpressionAttributeValues
        if ":status" in values:
            item["status"] = values[":status"]
        elif ":mapped" in values:  # a stale fix reopened
            item["status"] = "mapped"
        if ":pf" in values:
            item["proposed_fix"] = values[":pf"]
        if ":by" in values:
            item["superseded_by"] = values[":by"]
        if ":reason" in values:
            item["not_drafted_reason"] = values[":reason"]


    def put_item(self, Item):
        self.events = getattr(self, "events", []) + [Item]


class FakeS3:
    def __init__(self, objects):
        self.objects = dict(objects)

    def get_object(self, Bucket, Key, Range=None):
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        data = self.objects[Key]
        return {"Body": io.BytesIO(data if isinstance(data, bytes) else data.encode())}

    def put_object(self, Bucket, Key, Body, **kw):
        self.objects[Key] = Body

    def copy_object(self, Bucket, Key, CopySource):
        self.objects[Key] = self.objects[CopySource["Key"]]


def source_map(paths):
    return json.dumps({"resources": {f"L{i}": {"path": p} for i, p in enumerate(paths)}})


class World:
    """DynamoDB, S3, the scanner and the model, faked together."""

    def __init__(self, items, drafts, scans):
        self.table = FakeTable(items)
        self.s3 = FakeS3({
            f"scans/{PR}/{SOURCE}": ORIGINAL,
            f"scans/{PR}/{TEMPLATE}": json.dumps({"Resources": {"X": {"Type": "AWS::S3::Bucket"}}}),
            f"scans/{PR}/{TEMPLATE[:-5]}.sources": source_map([DATA, LOGS]),
        })
        self.drafts = list(drafts)    # model responses, in order
        self.scans = list(scans)      # (scanner findings, construct paths) per re-synth, in order
        self.prompts, self.scanned = [], []

    def invoke(self, FunctionName, InvocationType, Payload):
        payload = json.loads(Payload)
        self.scanned.append(payload["s3_prefix"])
        findings, paths = self.scans.pop(0)
        self.s3.objects[payload["s3_prefix"] + TEMPLATE[:-5] + ".sources"] = source_map(paths)
        return {"Payload": io.BytesIO(json.dumps({"findings": findings, "scan_errors": []}).encode())}

    def create(self, **kw):
        self.prompts.append(kw["messages"][0]["content"])
        content = self.drafts.pop(0)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps({
            "corrected_file_content": content, "rationale": "fixed", "assumptions": [], "questions": []}))])

    def __enter__(self):
        dynamodb = SimpleNamespace(Table=lambda name: self.table)
        client = SimpleNamespace(messages=SimpleNamespace(create=self.create))
        self.patches = [patch.object(handler, "dynamodb", dynamodb), patch.object(handler, "s3", self.s3),
                        patch.object(handler, "lambda_client", SimpleNamespace(invoke=self.invoke)),
                        patch.object(handler, "_get_anthropic_client", lambda: client),
                        patch.object(handler, "CONTEXT_AGENT_FUNCTION_NAME", None)]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()

    def status(self, fid):
        return self.table.items[f"FINDING#{fid}"]["status"]


def first_event():
    return {"pr_id": PR, "file": SOURCE,
            "synth": [{"app_dir": "infra", "status": "ok", "run_id": RUN, "templates": [TEMPLATE]}],
            "cdk_runs": [{"app_dir": "infra", "project_key": PROJECT}]}


def resumed(out, status="ok", **extra):
    """What the state machine passes back after running out["sandbox"]."""
    event = {k: v for k, v in out.items() if k != "sandbox"}
    event["sandbox_result"] = {"status": status, "templates": [TEMPLATE], **extra}
    return event


def scanned(*triples):
    return [{"finding_id": f"r{i}", "source": s, "rule_id": r, "resource": res, "title": f"title of {r}"}
            for i, (s, r, res) in enumerate(triples)]


def items():
    return [finding(B1, "AWS-0086", DATA, 2), finding(B2, "CKV_AWS_18", DATA, 2, severity="UNKNOWN", source="checkov"),
            finding(K1, "AWS-0132", LOGS, 3)]


def test_a_file_is_fixed_one_resource_at_a_time_through_the_sandbox():
    fix_data = ORIGINAL.replace("'Data')", "'Data', { versioned: true })")
    fix_logs_1 = fix_data.replace("'Logs')", "'Logs', { encryptionKey: new kms.Key(scope, 'LogsKey') })")
    fix_logs_2 = fix_logs_1.replace("new kms.Key(scope, 'LogsKey')", "new kms.Key(scope, 'LogsKey', { enableKeyRotation: true })")
    world = World(items(), drafts=[fix_data, fix_logs_1, fix_logs_2], scans=[
        # the bucket's fix: both its findings gone, the log bucket's still there
        (scanned(("trivy", "AWS-0132", LOGS)), [DATA, LOGS]),
        # the log bucket's first draft: cleared, but its new key has no rotation
        (scanned(("trivy", "AWS-0065", "/ProbeStack/LogsKey/Resource")), [DATA, LOGS, "/ProbeStack/LogsKey/Resource"]),
        # the redraft: nothing left
        (scanned(), [DATA, LOGS, "/ProbeStack/LogsKey/Resource"]),
    ])
    with world:
        out = handler.handler(first_event(), None)
        # 1. The bucket, most severe finding first: drafted and handed to the sandbox.
        req = out["sandbox"]
        assert req == {"kind": "cdk-resynth", "phases": ["execute"], "timeout_seconds": 600, "pr_id": PR,
                       "app_dir": "infra", "project_key": PROJECT, "deps_run_id": RUN, "finding_id": B1,
                       "patch_path": SOURCE, "attempt": 1}
        assert world.s3.objects[f"fixes/{PR}/{B1}/{SOURCE}"] == fix_data.encode()
        assert "AWS-0086" in world.prompts[0] and "CKV_AWS_18" in world.prompts[0]
        assert world.status(B1) == "mapped"  # nothing decided until the re-synth is scanned

        # 2. Re-synthesized: both bucket findings cleared; the next resource is drafted.
        out = handler.handler(resumed(out), None)
        assert world.scanned == [f"fixes/{PR}/{B1}/synth-1/"]
        assert world.status(B1) == "fix-proposed" and world.status(B2) == "superseded"
        fix = world.table.items[f"FINDING#{B1}"]["proposed_fix"]
        assert fix["file"] == SOURCE and fix["self_check_passed"] and fix["applies_after"] == []
        assert out["sandbox"]["finding_id"] == K1

        # 3. The log bucket's fix brought a finding on the key it made: one redraft.
        out = handler.handler(resumed(out), None)
        assert out["sandbox"]["attempt"] == 2 and out["sandbox"]["finding_id"] == K1
        assert "AWS-0065" in world.prompts[2] and "previous draft" in world.prompts[2]
        assert world.status(K1) == "mapped"

        # 4. The redraft is clean, and chained on the bucket's fix.
        out = handler.handler(resumed(out), None)
        assert world.scanned[-1] == f"fixes/{PR}/{K1}/synth-2/"
        assert "sandbox" not in out and out["remaining"] == 0
        assert world.status(K1) == "fix-proposed"
        fix = world.table.items[f"FINDING#{K1}"]["proposed_fix"]
        assert [a["finding_id"] for a in fix["applies_after"]] == [B1]
        assert out["fix_proposed_count"] == 2 and out["superseded_count"] == 1


def test_new_findings_still_there_after_the_redraft_hold_the_fix():
    key = "/ProbeStack/LogsKey/Resource"
    world = World([finding(K1, "AWS-0132", LOGS, 3)], drafts=["a", "b"], scans=[
        (scanned(("trivy", "AWS-0065", key)), [DATA, LOGS, key]),
        (scanned(("trivy", "AWS-0065", key)), [DATA, LOGS, key]),
    ])
    with world:
        out = handler.handler(first_event(), None)
        out = handler.handler(resumed(out), None)
        out = handler.handler(resumed(out), None)
    fix = world.table.items[f"FINDING#{K1}"]["proposed_fix"]
    assert world.status(K1) == "needs-human-only"
    assert fix["cleared"] is True and fix["self_check_new_findings"] == [f"trivy:AWS-0065 on {key}"]
    assert "sandbox" not in out


def test_a_finding_the_fix_did_not_clear_is_left_for_the_next_run():
    world = World(items()[:2], drafts=["fixed"], scans=[
        (scanned(("checkov", "CKV_AWS_18", DATA)), [DATA, LOGS]),
    ])
    with world:
        out = handler.handler(first_event(), None)
        handler.handler(resumed(out), None)
    assert world.status(B1) == "fix-proposed"
    assert world.status(B2) == "not-drafted"
    assert "did not clear it" in world.table.items[f"FINDING#{B2}"]["not_drafted_reason"]


def test_the_fix_is_held_on_the_first_finding_it_cleared():
    world = World(items()[:2], drafts=["fixed"], scans=[
        (scanned(("trivy", "AWS-0086", DATA)), [DATA, LOGS]),
    ])
    with world:
        out = handler.handler(first_event(), None)
        handler.handler(resumed(out), None)
    # B1 led the draft, but only B2 cleared: the fix is on B2, copied there.
    assert world.status(B2) == "fix-proposed"
    assert world.s3.objects[f"fixes/{PR}/{B2}/{SOURCE}"] == b"fixed"
    assert world.status(B1) == "not-drafted"


def test_a_construct_the_fix_removed_holds_it_for_review():
    world = World(items()[:2], drafts=["no bucket"], scans=[(scanned(), [LOGS])])
    with world:
        out = handler.handler(first_event(), None)
        handler.handler(resumed(out), None)
    fix = world.table.items[f"FINDING#{B1}"]["proposed_fix"]
    assert world.status(B1) == "needs-human-only" and fix["dropped_resources"] == [DATA]
    # The rescan did clear it, so the finding it took with it is superseded.
    assert world.status(B2) == "superseded"


@pytest.mark.parametrize("status,reason", [("failed", "the app exited 1"), ("error", "States.Timeout")])
def test_a_fix_that_does_not_synthesize_is_unverified(status, reason):
    world = World(items()[:2], drafts=["broken"], scans=[])
    with world:
        out = handler.handler(first_event(), None)
        out = handler.handler(resumed(out, status=status, reason=reason), None)
    fix = world.table.items[f"FINDING#{B1}"]["proposed_fix"]
    assert world.status(B1) == "needs-human-only"
    assert fix["scan_errors"] == [f"the fixed app did not synthesize ({status}): {reason}"]
    assert world.status(B2) == "not-drafted"
    assert world.scanned == []


@pytest.mark.parametrize("suppression", [
    "Bucket.node.addMetadata('checkov', { skip: [{ id: 'CKV_AWS_18' }] });",
    "NagSuppressions.addResourceSuppressions(bucket, [{ id: 'AwsSolutions-S1' }]);",
    "// checkov:skip=CKV_AWS_18",
])
def test_a_fix_that_silences_the_scanner_never_reaches_the_sandbox(suppression):
    world = World(items()[:2], drafts=[ORIGINAL + suppression + "\n"], scans=[])
    with world:
        out = handler.handler(first_event(), None)
    assert "sandbox" not in out
    fix = world.table.items[f"FINDING#{B1}"]["proposed_fix"]
    assert world.status(B1) == "needs-human-only" and fix["suppression_attempt"]
    assert world.status(B2) == "not-drafted"


def test_a_finding_about_the_whole_stack_is_not_drafted():
    stack_level = finding(S1, "8d29754a", None, 4, source="kics", file=SOURCE)
    world = World([stack_level], drafts=[], scans=[])
    with world:
        out = handler.handler(first_event(), None)
    assert "sandbox" not in out and world.status(S1) == "not-drafted"
    assert "stack as a whole" in world.table.items[f"FINDING#{S1}"]["not_drafted_reason"]


def test_without_a_synth_this_run_nothing_is_drafted():
    world = World(items(), drafts=[], scans=[])
    with world:
        event = first_event()
        event["synth"] = [{"app_dir": "infra", "status": "unavailable", "templates": []}]
        out = handler.handler(event, None)
    assert "sandbox" not in out
    assert {world.status(f) for f in (B1, B2, K1)} == {"not-drafted"}
    assert world.prompts == []


def test_the_budget_counts_model_calls(monkeypatch):
    monkeypatch.setattr(handler, "MAX_DRAFTS_PER_FILE", 1)
    world = World(items(), drafts=["fixed"], scans=[(scanned(("trivy", "AWS-0132", LOGS)), [DATA, LOGS])])
    with world:
        out = handler.handler(first_event(), None)
        out = handler.handler(resumed(out), None)
    assert world.status(B1) == "fix-proposed"
    assert world.status(K1) == "not-drafted" and "sandbox" not in out


def test_only_a_cdk_source_takes_this_path():
    assert handler._is_cdk_source("infra/lib/storage.ts")
    assert not handler._is_cdk_source("main.tf") and not handler._is_cdk_source(None)


def test_a_fix_drafted_on_an_older_file_is_reopened_and_redrafted():
    stale = finding(B1, "AWS-0086", DATA, 2)
    stale.update(status="fix-proposed", proposed_fix={
        "diff": "-old\n+new", "file": SOURCE, "base_sha256": "not-the-current-file"})
    world = World([stale], drafts=["fixed again"], scans=[])
    with world:
        out = handler.handler(first_event(), None)
    # Back to mapped, on the record and in the audit trail, then redrafted.
    assert world.table.events and "stale" in json.dumps(world.table.events[0])
    assert out["sandbox"]["finding_id"] == B1
    assert world.s3.objects[f"fixes/{PR}/{B1}/{SOURCE}"] == b"fixed again"
