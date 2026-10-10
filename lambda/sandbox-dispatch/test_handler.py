import io
import json

import pytest
from botocore.exceptions import ClientError

import handler
import leak


class FakeS3:
    def __init__(self, objects=None):
        self.objects = objects or {}
        self.gets = []

    def put_object(self, Bucket, Key, Body, ContentType):
        assert Bucket == "sb" and Key.startswith("runs/")
        self.objects[Key] = Body

    def generate_presigned_url(self, op, Params, ExpiresIn):
        return f"https://{Params['Bucket']}.s3.test/{Params['Key']}?op={op}&exp={ExpiresIn}&X-Amz-Signature=sig"

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ContentLength": len(self.objects[Key])}

    def get_object(self, Bucket, Key, Range):
        self.gets.append(Range)
        end = int(Range.split("-")[1])
        return {"Body": io.BytesIO(self.objects[Key][: end + 1])}


class FakeCodeArtifact:
    def __init__(self):
        self.token_calls = 0

    def get_repository_endpoint(self, **kw):
        return {"repositoryEndpoint": "https://dom-123.d.codeartifact.us-east-1.amazonaws.com/npm/npm-mirror/"}

    def get_authorization_token(self, **kw):
        self.token_calls += 1
        assert kw["durationSeconds"] == 900
        return {"authorizationToken": "ca-token"}


class FakeECS:
    def __init__(self, running=None):
        self.running = dict(running or {})  # arn -> group
        self.stopped = []

    def describe_tasks(self, cluster, tasks):
        assert len(tasks) <= 100
        return {"tasks": [{"taskArn": a, "group": self.running[a]} for a in tasks]}

    def get_paginator(self, name):
        assert name == "list_tasks"
        ecs = self

        class P:
            def paginate(self, **kw):
                assert kw["desiredStatus"] == "RUNNING"
                yield {"taskArns": list(ecs.running)}
        return P()

    def stop_task(self, cluster, task, reason):
        self.stopped.append(task)


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    s3, ca, ecs = FakeS3(), FakeCodeArtifact(), FakeECS()
    monkeypatch.setattr(handler, "s3", s3)
    monkeypatch.setattr(handler, "codeartifact", ca)
    monkeypatch.setattr(handler, "ecs", ecs)
    monkeypatch.setattr(handler, "_npm_endpoint", None)
    monkeypatch.setattr(handler, "SANDBOX_BUCKET", "sb")
    monkeypatch.setattr(handler, "CANARY_BUCKET", "canary")
    # collect resolves names from outside the sandbox; never for real here.
    monkeypatch.setattr(handler, "_resolves", lambda name: "resolved")
    return s3, ca, ecs


def env_of(prepared, phase):
    return {e["Name"]: e["Value"] for e in prepared["prepared"]["env"][phase]}


def manifest_of(fakes, prepared, phase):
    run_id = prepared["prepared"]["run_id"]
    return json.loads(fakes[0].objects[f"runs/{run_id}/{phase}/manifest.json"])


# --- prepare ---------------------------------------------------------------

def test_prepare_returns_the_executions_initial_state(fakes):
    out = handler.handler({"action": "prepare", "kind": "leak-test",
                           "phases": ["execute", "fetch"], "timeout_seconds": 120}, None)
    p = out["prepared"]
    assert handler.RUN_ID_RE.match(p["run_id"])
    assert p["group"] == "sandbox:" + p["run_id"]
    # Always fetch first, whatever order was asked.
    assert p["phases"] == ["fetch", "execute"]
    assert p["run_fetch"] and p["run_execute"]
    assert out["timeout_seconds"] == 120
    assert out["tasks"] == {} and out["errors"] == {}


def test_urls_name_only_the_runs_own_objects_and_outlive_the_task(fakes):
    out = handler.prepare({"kind": "leak-test", "phases": ["execute"], "timeout_seconds": 120})
    run_id = out["prepared"]["run_id"]
    env = manifest_of(fakes, out, "execute")
    assert f"sb.s3.test/runs/{run_id}/execute/result.json" in env["RESULT_URL"]
    assert f"sb.s3.test/runs/{run_id}/execute/output.tgz" in env["OUTPUT_URL"]
    assert "exp=720" in env["RESULT_URL"]  # 120 + the start allowance


def test_phase_is_never_sent_because_an_override_would_win(fakes):
    out = handler.prepare({"kind": "leak-test", "phases": ["fetch", "execute"], "timeout_seconds": 60})
    for phase in ("fetch", "execute"):
        assert "SANDBOX_PHASE" not in env_of(out, phase)


def test_only_the_fetch_task_gets_the_codeartifact_token(fakes):
    _, ca, _ = fakes
    out = handler.prepare({"kind": "sleep", "phases": ["fetch", "execute"], "timeout_seconds": 60})
    assert manifest_of(fakes, out, "fetch")["CODEARTIFACT_TOKEN"] == "ca-token"
    assert "CODEARTIFACT_TOKEN" not in manifest_of(fakes, out, "execute")
    assert "CODEARTIFACT_NPM_URL" not in manifest_of(fakes, out, "execute")
    # The host is not a secret, and execute needs it to probe it cannot reach it.
    assert manifest_of(fakes, out, "execute")["CODEARTIFACT_HOST"] == "dom-123.d.codeartifact.us-east-1.amazonaws.com"
    assert ca.token_calls == 1


def test_leak_test_gets_a_valid_canary_and_an_unsigned_foreign_key(fakes):
    out = handler.prepare({"kind": "leak-test", "phases": ["execute"], "timeout_seconds": 60})
    env = manifest_of(fakes, out, "execute")
    assert env["CANARY_URL"].startswith("https://canary.s3.test/")
    assert "X-Amz-Signature" in env["CANARY_URL"]
    assert env["FOREIGN_URL"].startswith("https://sb.s3.")
    assert out["prepared"]["run_id"] not in env["FOREIGN_URL"]
    assert "X-Amz-" not in env["FOREIGN_URL"]


def test_only_leak_tests_get_the_probe_targets(fakes):
    env = manifest_of(fakes, handler.prepare({"kind": "sleep", "phases": ["execute"], "timeout_seconds": 60}), "execute")
    assert "CANARY_URL" not in env and "FOREIGN_URL" not in env


@pytest.mark.parametrize("request_", [
    {"kind": "cdk-synth", "phases": ["execute"], "timeout_seconds": 60},
    {"kind": "leak-test", "phases": [], "timeout_seconds": 60},
    {"kind": "leak-test", "phases": ["execute", "execute"], "timeout_seconds": 60},
    {"kind": "leak-test", "phases": ["deploy"], "timeout_seconds": 60},
    {"kind": "leak-test", "phases": ["execute"], "timeout_seconds": 5},
    {"kind": "leak-test", "phases": ["execute"], "timeout_seconds": 99999},
    {"kind": "leak-test", "phases": ["execute"], "timeout_seconds": True},
    {"kind": "leak-test", "phases": ["execute"], "timeout_seconds": "60"},
])
def test_prepare_refuses_what_it_does_not_run(request_):
    with pytest.raises(handler.BadRequest):
        handler.prepare(request_)


def test_unknown_action_is_refused():
    with pytest.raises(handler.BadRequest):
        handler.handler({"action": "run-anything"}, None)


# --- reap --------------------------------------------------------------------

RUN = "0123456789abcdef0123456789abcdef"


def test_reap_stops_this_runs_tasks_and_no_others(fakes):
    _, _, ecs = fakes
    other = "f" * 32
    ecs.running = {"arn:task/1": "sandbox:" + RUN, "arn:task/2": "sandbox:" + other,
                   "arn:task/3": "family:x"}
    assert handler.reap({"group": "sandbox:" + RUN}) == {"stopped": ["arn:task/1"]}
    assert ecs.stopped == ["arn:task/1"]


def test_reap_describes_in_batches_of_a_hundred(fakes):
    _, _, ecs = fakes
    ecs.running = {f"arn:task/{i}": "sandbox:" + RUN for i in range(150)}
    assert len(handler.reap({"group": "sandbox:" + RUN})["stopped"]) == 150


def test_reap_with_nothing_running_stops_nothing(fakes):
    _, _, ecs = fakes
    assert handler.reap({"group": "sandbox:" + RUN}) == {"stopped": []}
    assert ecs.stopped == []


@pytest.mark.parametrize("group", ["", "family:x", "sandbox:", "sandbox:" + RUN + "x", RUN, "sandbox-" + RUN])
def test_reap_only_touches_sandbox_runs(group):
    with pytest.raises(handler.BadRequest):
        handler.reap({"group": group})


# --- collect -----------------------------------------------------------------

def result(phase="execute", kind="leak-test", probes=None):
    return json.dumps({"phase": phase, "kind": kind,
                       "probes": probes if probes is not None else [{"name": "fs.uid", "observed": "1000"}]}).encode()


def put(fakes, body, phase="execute"):
    fakes[0].objects[f"runs/{RUN}/{phase}/result.json"] = body


def collect(phases=("execute",), kind="leak-test", **kw):
    return handler.collect({"run_id": RUN, "kind": kind, "phases": list(phases), **kw})


def test_collect_reads_a_well_formed_result(fakes):
    put(fakes, result(kind="sleep"))
    rec = collect(kind="sleep")["phases"]["execute"]
    assert rec["status"] == "ok"
    assert rec["result"]["probes"] == [{"name": "fs.uid", "observed": "1000"}]


def test_a_missing_result_is_a_status_not_an_error(fakes):
    assert collect(kind="sleep")["phases"]["execute"]["status"] == "missing"


def test_an_oversized_result_is_never_read(fakes):
    put(fakes, b"x" * (handler.MAX_RESULT_BYTES + 1))
    rec = collect(kind="sleep")["phases"]["execute"]
    assert rec["status"] == "oversized"
    assert fakes[0].gets == []


@pytest.mark.parametrize("body,why", [
    (b"\xff\xfe not utf-8", "not UTF-8 JSON"),
    (b"{not json", "not UTF-8 JSON"),
    (b"[]", "not an object"),
    (result(phase="fetch"), "phase or kind does not match the run"),
    (result(kind="leak-test"), "phase or kind does not match the run"),
    (result(kind="sleep", probes={"a": 1}), "probes is not a list"),
    (result(kind="sleep", probes=[{"name": "a"}]), "a probe without"),
    (result(kind="sleep", probes=[{"name": 1, "observed": "x"}]), "a probe without"),
    (result(kind="sleep", probes=[{"name": "a", "observed": "x"}] * 2), "repeated"),
    (result(kind="sleep", probes=[{"name": "n" * 65, "observed": "x"}]), "too long"),
    (result(kind="sleep", probes=[{"name": f"p{i}", "observed": "x"} for i in range(101)]), "at most"),
])
def test_hostile_results_are_malformed_not_crashes(fakes, body, why):
    put(fakes, body)
    rec = collect(kind="sleep")["phases"]["execute"]
    assert rec["status"] == "malformed"
    assert why in rec["why"]


def test_long_observations_are_clipped_and_unknown_fields_dropped(fakes):
    put(fakes, result(kind="sleep", probes=[{"name": "a", "observed": "o" * 1000,
                                             "detail": "d" * 1000, "extra": "<script>"}]))
    (probe,) = collect(kind="sleep")["phases"]["execute"]["result"]["probes"]
    assert set(probe) == {"name", "observed", "detail"}
    assert len(probe["observed"]) == handler.MAX_OBSERVED + 1
    assert len(probe["detail"]) == handler.MAX_DETAIL + 1


def test_collect_summarises_tasks_errors_and_reaping(fakes):
    out = collect(kind="sleep",
                  tasks={"execute": {"task_arn": "arn:t", "containers": [
                      {"Name": "job", "ExitCode": 0, "LastStatus": "STOPPED", "Reason": None}]}},
                  errors={"fetch": {"Error": "States.Timeout", "Cause": "c" * 2000}},
                  reap={"stopped": ["arn:t2"]}, phases=("execute",))
    assert out["phases"]["execute"]["task"] == {"task_arn": "arn:t", "containers": [
        {"name": "job", "exit_code": 0, "last_status": "STOPPED", "reason": None}]}
    assert out["reaped"] == ["arn:t2"]
    assert "leak" not in out


def test_collect_refuses_a_run_id_it_did_not_mint():
    with pytest.raises(handler.BadRequest):
        handler.collect({"run_id": "../../other", "kind": "sleep", "phases": ["execute"]})


def passing_probes(phase):
    """What a contained task observes, per the table."""
    values = {"eq": lambda v: v, "prefix": lambda v: v + ":x",
              "ne": lambda v: "not-" + v, "not_prefix": lambda v: "other"}
    probes = {}
    for name, phases, op, value, _, _ in leak.EXPECTATIONS:
        if phase in phases:
            probes[name] = values[op](value)
    return [{"name": n, "observed": o} for n, o in probes.items()]


def test_collect_grades_a_leak_test(fakes):
    for phase in ("fetch", "execute"):
        put(fakes, result(phase=phase, probes=passing_probes(phase)), phase)
    out = collect(phases=("fetch", "execute"))
    assert out["leak"]["passed"], [c for c in out["leak"]["checks"] if not c["passed"]]


# --- leak.evaluate -------------------------------------------------------------

def ok(probes):
    return {"status": "ok", "result": {"probes": probes}}


OUTSIDE_OK = {p: {"dns.example.com": "resolved", "dns.unique": "resolved"} for p in ("fetch", "execute")}


def test_every_expectation_is_satisfiable_and_the_fixture_passes():
    graded = leak.evaluate({p: ok(passing_probes(p)) for p in ("fetch", "execute")}, OUTSIDE_OK)
    assert graded["passed"]
    assert graded["unknown_probes"] == []


def test_a_probe_that_did_not_run_fails():
    probes = [p for p in passing_probes("execute") if p["name"] != "s3.canary"]
    graded = leak.evaluate({"execute": ok(probes)}, OUTSIDE_OK)
    assert not graded["passed"]
    (failed,) = [c for c in graded["checks"] if not c["passed"]]
    assert failed["probe"] == "s3.canary" and failed["observed"] == "(not reported)"


def test_a_phase_without_a_result_fails_every_check():
    graded = leak.evaluate({"execute": {"status": "missing"}})
    assert not graded["passed"]
    assert all(c["observed"].startswith("(no result: missing)") for c in graded["checks"])


def test_a_dead_network_fails_the_controls_even_though_every_leak_check_passes():
    probes = []
    for p in passing_probes("execute"):
        dead = p["name"] in {"dns.endpoint", "s3.own_put"}
        probes.append({"name": p["name"], "observed": "timeout" if dead else p["observed"]})
    graded = leak.evaluate({"execute": ok(probes)}, OUTSIDE_OK)
    failed = {c["probe"] for c in graded["checks"] if not c["passed"]}
    assert failed == {"dns.endpoint", "s3.own_put"}
    assert all(c["control"] for c in graded["checks"] if not c["passed"])


@pytest.mark.parametrize("probe,observed", [
    ("tcp.1.1.1.1:443", "connected"),
    ("dns.unique", "resolved"),
    ("s3.canary", "http:200"),
    ("env.credentials", "AWS_ACCESS_KEY_ID"),
    ("creds_endpoint", "credentials"),
    ("fs.uid", "0"),
    ("fs.fresh", "stale"),
    ("tmde.secrets", "present"),
])
def test_each_leak_fails_the_run(probe, observed):
    probes = [{"name": p["name"], "observed": observed if p["name"] == probe else p["observed"]}
              for p in passing_probes("execute")]
    assert not leak.evaluate({"execute": ok(probes)}, OUTSIDE_OK)["passed"]


def test_the_mirror_is_a_control_for_fetch_and_a_leak_for_execute():
    rows = {(name, phases): control for name, phases, _, _, control, _ in leak.EXPECTATIONS
            if name == "codeartifact.reach"}
    assert rows == {("codeartifact.reach", ("fetch",)): True, ("codeartifact.reach", ("execute",)): False}


def test_unknown_probes_are_reported_not_failed():
    graded = leak.evaluate({"execute": ok(passing_probes("execute") + [{"name": "new.probe", "observed": "x"},
                                                                      {"name": "env.names", "observed": "A,B"}])},
                           OUTSIDE_OK)
    assert graded["passed"]
    assert graded["unknown_probes"] == ["execute:new.probe"]


def test_environment_is_pascal_case_for_step_functions(fakes):
    # ECS spells these name/value; the Step Functions integration refuses
    # anything but Name/Value, and the run fails before a task starts.
    out = handler.prepare({"kind": "sleep", "phases": ["fetch", "execute"], "timeout_seconds": 60})
    for phase in ("fetch", "execute"):
        assert all(set(e) == {"Name", "Value"} for e in out["prepared"]["env"][phase])


def test_the_environment_holds_no_credential_only_the_manifest_url(fakes):
    # Overrides are capped at 8192 characters and shown in full in the
    # execution history and the task description.
    out = handler.prepare({"kind": "leak-test", "phases": ["fetch", "execute"], "timeout_seconds": 60})
    for phase in ("fetch", "execute"):
        env = env_of(out, phase)
        assert set(env) == {"SANDBOX_RUN_ID", "SANDBOX_KIND", "MANIFEST_URL"}
        assert f"runs/{out['prepared']['run_id']}/{phase}/manifest.json" in env["MANIFEST_URL"]
        assert "op=get_object" in env["MANIFEST_URL"]
        assert "ca-token" not in json.dumps(out)



# --- the DNS checks must be able to fail ---------------------------------------

def test_a_dns_check_on_a_name_that_resolves_nowhere_is_inconclusive():
    # The first deployed leak test passed dns.unique on a name under
    # example.org, which fails to resolve with or without a firewall.
    outside = {"execute": {"dns.example.com": "resolved", "dns.unique": "dns-fail"}}
    graded = leak.evaluate({"execute": ok(passing_probes("execute"))}, outside)
    (failed,) = [c for c in graded["checks"] if not c["passed"]]
    assert failed["probe"] == "dns.unique"
    assert "inconclusive" in failed["observed"]


def test_without_an_outside_check_the_dns_checks_fail():
    graded = leak.evaluate({"execute": ok(passing_probes("execute"))})
    failed = {c["probe"] for c in graded["checks"] if not c["passed"]}
    assert failed == leak.OUTSIDE_REQUIRED


def test_the_unique_name_resolves_publicly_by_construction(fakes):
    out = handler.prepare({"kind": "leak-test", "phases": ["fetch", "execute"], "timeout_seconds": 60})
    run_id = out["prepared"]["run_id"]
    for phase in ("fetch", "execute"):
        m = manifest_of(fakes, out, phase)
        assert m["DNS_UNIQUE_NAME"] == f"{run_id}-{phase}.127.0.0.1.nip.io"
        assert m["DNS_PUBLIC_NAME"] == "example.com"
        # A DNS label is at most 63 characters.
        assert all(len(label) <= 63 for label in m["DNS_UNIQUE_NAME"].split("."))


def test_collect_checks_the_dns_names_from_outside(fakes, monkeypatch):
    asked = []
    monkeypatch.setattr(handler, "_resolves", lambda name: asked.append(name) or "resolved")
    for phase in ("fetch", "execute"):
        put(fakes, result(phase=phase, probes=passing_probes(phase)), phase)
    out = collect(phases=("fetch", "execute"))
    assert out["leak"]["passed"]
    assert "example.com" in asked
    assert {f"{RUN}-fetch.127.0.0.1.nip.io", f"{RUN}-execute.127.0.0.1.nip.io"} <= set(asked)


def test_collect_fails_a_leak_test_whose_names_do_not_resolve_outside(fakes, monkeypatch):
    monkeypatch.setattr(handler, "_resolves", lambda name: "dns-fail")
    put(fakes, result(probes=passing_probes("execute")))
    assert not collect()["leak"]["passed"]


def test_a_task_failure_reports_why_it_stopped_not_its_attachments(fakes):
    # The first 500 characters of a failed task's cause are its network
    # attachments; the reason comes late (2026-10-10).
    cause = json.dumps({"Attachments": [{"Details": [{"Name": "x", "Value": "y" * 600}]}],
                        "StopCode": "TaskFailedToStart",
                        "StoppedReason": "CannotPullContainerError: lookup ... no such host"})
    out = collect(kind="sleep", errors={"execute": {"Error": "States.TaskFailed", "Cause": cause}})
    assert out["phases"]["execute"]["error"] == {
        "error": "States.TaskFailed", "stop_code": "TaskFailedToStart",
        "stopped_reason": "CannotPullContainerError: lookup ... no such host"}


def test_a_non_task_cause_is_kept_clipped(fakes):
    out = collect(kind="sleep", errors={"execute": {"Error": "States.Timeout", "Cause": "c" * 2000}})
    err = out["phases"]["execute"]["error"]
    assert err["error"] == "States.Timeout" and len(err["cause"]) == handler.MAX_CAUSE + 1
