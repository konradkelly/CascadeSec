"""Tests for webhook-receiver's handler. Secrets Manager and Step Functions
are mocked -- no AWS calls."""

import base64
import hashlib
import hmac
import json
import re
from unittest.mock import MagicMock, patch

import pytest

import handler


SECRET = "0123456789abcdef" * 4
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40


class ExecutionAlreadyExists(Exception):
    pass


class ResourceNotFoundException(Exception):
    pass


def _pr_payload(action="opened", draft=False, head_sha=HEAD_SHA):
    return {
        "action": action,
        "number": 7,
        "pull_request": {
            "number": 7,
            "draft": draft,
            "head": {"sha": head_sha, "ref": "feature"},
            "base": {"sha": BASE_SHA, "ref": "main"},
        },
        "repository": {"id": 123456, "full_name": "konradkelly/cascadesec-testbed"},
        "installation": {"id": 987},
    }


def _sign(body, secret=SECRET):
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _event(payload, gh_event="pull_request", signature=None, raw=None, b64=False):
    body = raw if raw is not None else json.dumps(payload).encode()
    headers = {
        # HTTP API lowercases header names; the handler must not depend on it.
        "X-GitHub-Event": gh_event,
        "X-GitHub-Delivery": "delivery-1",
    }
    headers["X-Hub-Signature-256"] = _sign(body) if signature is None else signature
    return {
        "headers": headers,
        "body": base64.b64encode(body).decode() if b64 else body.decode(),
        "isBase64Encoded": b64,
    }


@pytest.fixture(autouse=True)
def aws():
    handler._secret_cache.update(value=None, fetched_at=0.0)
    with patch.object(handler, "secretsmanager") as sm, patch.object(handler, "sfn") as sfn:
        sm.exceptions.ResourceNotFoundException = ResourceNotFoundException
        sm.get_secret_value.return_value = {"SecretString": SECRET + "\n"}
        sfn.exceptions.ExecutionAlreadyExists = ExecutionAlreadyExists
        yield sm, sfn


# ---------- authentication ----------

def test_valid_signature_starts_an_execution(aws):
    _, sfn = aws
    response = handler.handler(_event(_pr_payload()), None)

    assert response["statusCode"] == 202
    sfn.start_execution.assert_called_once()


def test_tampered_body_is_rejected_before_anything_starts(aws):
    _, sfn = aws
    signed = json.dumps(_pr_payload()).encode()
    tampered = signed.replace(b"987", b"988")
    response = handler.handler(_event(None, raw=tampered, signature=_sign(signed)), None)

    assert response["statusCode"] == 401
    sfn.start_execution.assert_not_called()


def test_missing_signature_is_rejected(aws):
    event = _event(_pr_payload())
    del event["headers"]["X-Hub-Signature-256"]

    assert handler.handler(event, None)["statusCode"] == 401


def test_signature_with_the_wrong_secret_is_rejected(aws):
    body = json.dumps(_pr_payload()).encode()
    event = _event(None, raw=body, signature=_sign(body, secret="REPLACE_ME"))

    assert handler.handler(event, None)["statusCode"] == 401


def test_sha1_signature_header_is_not_accepted(aws):
    # X-Hub-Signature (SHA-1) is the legacy header; only -256 is checked.
    body = json.dumps(_pr_payload()).encode()
    sha1 = "sha1=" + hmac.new(SECRET.encode(), body, hashlib.sha1).hexdigest()

    assert handler.handler(_event(None, raw=body, signature=sha1), None)["statusCode"] == 401


def test_signature_is_checked_over_the_raw_bytes_not_reparsed_json(aws):
    # GitHub's bytes are not json.dumps's: different spacing, key order and
    # escaping. A check that re-serialised would reject this real-shaped body.
    raw = b'{"action":"opened", "number":7,"pull_request":{"number":7,"draft":false,' \
          b'"head":{"sha":"' + HEAD_SHA.encode() + b'"},"base":{"sha":"' + BASE_SHA.encode() + \
          b'"},"title":"caf\\u00e9"},"repository":{"id":123456,"full_name":"o/r"},' \
          b'"installation":{"id":987}}'

    assert handler.handler(_event(None, raw=raw), None)["statusCode"] == 202


def test_base64_encoded_body_is_decoded_before_the_check(aws):
    assert handler.handler(_event(_pr_payload(), b64=True), None)["statusCode"] == 202


def test_unparseable_body_is_not_parsed_until_signed(aws):
    # Garbage with a bad signature is a 401, not a 400: nothing is parsed
    # before authentication.
    event = _event(None, raw=b"not json", signature="sha256=" + "0" * 64)

    assert handler.handler(event, None)["statusCode"] == 401


def test_signed_garbage_is_a_400(aws):
    assert handler.handler(_event(None, raw=b"not json"), None)["statusCode"] == 400


# ---------- the secret ----------

def test_secret_without_a_value_fails_closed(aws):
    sm, sfn = aws
    sm.get_secret_value.side_effect = ResourceNotFoundException("no version")

    assert handler.handler(_event(_pr_payload()), None)["statusCode"] == 503
    sfn.start_execution.assert_not_called()


def test_empty_secret_fails_closed(aws):
    sm, _ = aws
    sm.get_secret_value.return_value = {"SecretString": "  \n"}

    assert handler.handler(_event(_pr_payload()), None)["statusCode"] == 503


def test_secret_is_cached_between_deliveries(aws):
    sm, _ = aws
    handler.handler(_event(_pr_payload()), None)
    handler.handler(_event(_pr_payload(head_sha="c" * 40)), None)

    assert sm.get_secret_value.call_count == 1


def test_forged_requests_do_not_refetch_the_secret(aws):
    sm, _ = aws
    for _ in range(5):
        handler.handler(_event(_pr_payload(), signature="sha256=" + "0" * 64), None)

    assert sm.get_secret_value.call_count == 1


def test_secret_is_refetched_after_its_ttl(aws):
    sm, _ = aws
    with patch.object(handler.time, "monotonic", side_effect=[1000.0, 1000.0 + handler.SECRET_TTL_SECONDS + 1]):
        handler.handler(_event(_pr_payload()), None)
        handler.handler(_event(_pr_payload()), None)

    assert sm.get_secret_value.call_count == 2


# ---------- which events are scanned ----------

def test_ping_is_answered(aws):
    _, sfn = aws
    response = handler.handler(_event({"zen": "Keep it logically awesome.", "hook_id": 1}, gh_event="ping"), None)

    assert response["statusCode"] == 200
    sfn.start_execution.assert_not_called()


@pytest.mark.parametrize("action", ["opened", "synchronize", "reopened", "ready_for_review"])
def test_scanned_actions_start_an_execution(aws, action):
    assert handler.handler(_event(_pr_payload(action=action)), None)["statusCode"] == 202


@pytest.mark.parametrize("action", ["closed", "edited", "labeled", "assigned", "converted_to_draft"])
def test_other_actions_are_ignored(aws, action):
    _, sfn = aws

    assert handler.handler(_event(_pr_payload(action=action)), None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()


def test_draft_pr_is_not_scanned(aws):
    _, sfn = aws

    assert handler.handler(_event(_pr_payload(draft=True)), None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()


@pytest.mark.parametrize("gh_event", ["push", "issues", "check_run", "installation"])
def test_other_events_are_ignored(aws, gh_event):
    _, sfn = aws

    assert handler.handler(_event(_pr_payload(), gh_event=gh_event), None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()


def test_payload_missing_installation_is_a_400(aws):
    payload = _pr_payload()
    del payload["installation"]

    assert handler.handler(_event(payload), None)["statusCode"] == 400


def test_non_sha_head_is_a_400(aws):
    # head_sha ends up in the execution name and, later, in an S3 key. Only a
    # real 40-hex sha gets that far.
    assert handler.handler(_event(_pr_payload(head_sha="../../main")), None)["statusCode"] == 400


# ---------- the execution ----------

def test_execution_input(aws):
    _, sfn = aws
    handler.handler(_event(_pr_payload()), None)

    kwargs = sfn.start_execution.call_args.kwargs
    assert json.loads(kwargs["input"]) == {
        "pr_id": "gh-123456-7",
        "s3_prefix": "scans/gh-123456-7/",
        "remediate": False,
        "github": {
            "installation_id": 987,
            "repository_id": 123456,
            "repository": "konradkelly/cascadesec-testbed",
            "pr_number": 7,
            "head_sha": HEAD_SHA,
            "base_sha": BASE_SHA,
            "trigger": "push",
        },
    }
    assert kwargs["name"] == "gh-123456-7-aaaaaaaaaaaa-push"


def test_redelivery_starts_nothing_new(aws):
    _, sfn = aws
    event = _event(_pr_payload())
    assert handler.handler(event, None)["statusCode"] == 202

    sfn.start_execution.side_effect = ExecutionAlreadyExists("same name")
    assert handler.handler(event, None)["statusCode"] == 200


def test_redelivery_sends_identical_input(aws):
    # Standard executions treat a same-name start with the same input
    # differently from one with different input; a redelivery must be the
    # former, so nothing per-delivery may leak into the input.
    _, sfn = aws
    first = _event(_pr_payload())
    second = _event(_pr_payload())
    second["headers"]["X-GitHub-Delivery"] = "delivery-2"
    handler.handler(first, None)
    handler.handler(second, None)

    a, b = (c.kwargs for c in sfn.start_execution.call_args_list)
    assert a == b


def test_new_push_gets_a_new_execution_name(aws):
    _, sfn = aws
    handler.handler(_event(_pr_payload()), None)
    handler.handler(_event(_pr_payload(action="synchronize", head_sha="c" * 40)), None)

    first, second = (c.kwargs["name"] for c in sfn.start_execution.call_args_list)
    assert first != second


def test_pr_id_cannot_collide_across_repositories():
    # The reason pr_id uses the numeric id: owner "a-b" + repo "c" and owner
    # "a" + repo "b-c" join to the same string.
    assert handler.make_pr_id(1, 12) != handler.make_pr_id(11, 2)


@pytest.mark.parametrize("pr_id", ["gh-123456-7", "gh-" + "9" * 70 + "-1", "weird id/with:chars"])
def test_execution_names_follow_step_functions_rules(pr_id):
    name = handler.execution_name(pr_id, HEAD_SHA, "push")

    assert re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name)


# ---------- check_run: Draft fixes and Re-run (spec §5) ----------

def _check_run_payload(action="requested_action", identifier="draft_fixes", name="CascadeSec",
                       pull_requests=True, head_sha=HEAD_SHA):
    payload = {
        "action": action,
        "check_run": {
            "id": 55, "name": name, "head_sha": head_sha,
            "pull_requests": [{"number": 7, "head": {"sha": "c" * 40}, "base": {"sha": BASE_SHA}}]
            if pull_requests else [],
        },
        "repository": {"id": 123456, "full_name": "konradkelly/cascadesec-testbed"},
        "installation": {"id": 987},
    }
    if action == "requested_action":
        payload["requested_action"] = {"identifier": identifier}
    return payload


def test_draft_fixes_starts_a_remediating_execution_on_the_check_runs_commit(aws):
    _, sfn = aws
    response = handler.handler(_event(_check_run_payload(), gh_event="check_run"), None)

    assert response["statusCode"] == 202
    kwargs = sfn.start_execution.call_args.kwargs
    execution_input = json.loads(kwargs["input"])
    assert execution_input["remediate"] is True
    # The commit the button was on, not the PR's newer head.
    assert execution_input["github"]["head_sha"] == HEAD_SHA
    assert execution_input["github"]["trigger"] == "fixes"
    assert kwargs["name"] == "gh-123456-7-aaaaaaaaaaaa-fixes"


def test_second_click_on_draft_fixes_starts_nothing(aws):
    _, sfn = aws
    sfn.start_execution.side_effect = ExecutionAlreadyExists("same")

    assert handler.handler(_event(_check_run_payload(), gh_event="check_run"), None)["statusCode"] == 200


def test_rerun_is_a_plain_rescan_named_by_its_delivery(aws):
    _, sfn = aws
    first = _event(_check_run_payload(action="rerequested"), gh_event="check_run")
    second = _event(_check_run_payload(action="rerequested"), gh_event="check_run")
    second["headers"]["X-GitHub-Delivery"] = "other-delivery"
    handler.handler(first, None)
    handler.handler(second, None)

    names = [c.kwargs["name"] for c in sfn.start_execution.call_args_list]
    inputs = [json.loads(c.kwargs["input"]) for c in sfn.start_execution.call_args_list]
    assert names[0] != names[1]
    assert all(i["remediate"] is False for i in inputs)
    assert names[0] == "gh-123456-7-aaaaaaaaaaaa-rerun-delivery"


def test_other_apps_check_runs_are_ignored(aws):
    # CI's own check runs arrive too; only ours has a button.
    _, sfn = aws
    event = _event(_check_run_payload(action="rerequested", name="build"), gh_event="check_run")

    assert handler.handler(event, None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()


def test_unknown_button_is_ignored(aws):
    _, sfn = aws
    event = _event(_check_run_payload(identifier="something_else"), gh_event="check_run")

    assert handler.handler(event, None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()


@pytest.mark.parametrize("action", ["created", "completed"])
def test_check_run_lifecycle_events_are_ignored(aws, action):
    # Every check run's created/completed arrives too: ~25 per push on a repo
    # with busy CI. None of them starts anything.
    _, sfn = aws
    payload = _check_run_payload(action=action)

    assert handler.handler(_event(payload, gh_event="check_run"), None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()


def test_check_run_without_a_pull_request_is_ignored(aws):
    # GitHub leaves pull_requests empty for a PR from a fork.
    _, sfn = aws
    event = _event(_check_run_payload(pull_requests=False), gh_event="check_run")

    assert handler.handler(event, None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()


def test_check_run_with_a_bad_sha_is_a_400(aws):
    event = _event(_check_run_payload(head_sha="../x"), gh_event="check_run")

    assert handler.handler(event, None)["statusCode"] == 400


def _check_suite_payload(action="rerequested", pull_requests=True):
    return {
        "action": action,
        "check_suite": {
            "id": 77, "head_sha": HEAD_SHA,
            "pull_requests": [{"number": 7, "head": {"sha": HEAD_SHA}, "base": {"sha": BASE_SHA}}]
            if pull_requests else [],
        },
        "repository": {"id": 123456, "full_name": "konradkelly/cascadesec-testbed"},
        "installation": {"id": 987},
    }


def test_suite_rerun_from_the_pr_page_is_a_rescan(aws):
    # The PR page's Re-run sends check_suite.rerequested, not check_run --
    # the first real click on PugetScope #10 was ignored for it.
    _, sfn = aws
    response = handler.handler(_event(_check_suite_payload(), gh_event="check_suite"), None)

    assert response["statusCode"] == 202
    kwargs = sfn.start_execution.call_args.kwargs
    execution_input = json.loads(kwargs["input"])
    assert execution_input["remediate"] is False
    assert execution_input["github"]["trigger"].startswith("rerun-")
    assert kwargs["name"] == "gh-123456-7-aaaaaaaaaaaa-rerun-delivery"


@pytest.mark.parametrize("action", ["requested", "completed"])
def test_other_check_suite_actions_are_ignored(aws, action):
    _, sfn = aws

    assert handler.handler(_event(_check_suite_payload(action=action), gh_event="check_suite"), None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()


def test_suite_rerun_without_a_pull_request_is_ignored(aws):
    _, sfn = aws
    event = _event(_check_suite_payload(pull_requests=False), gh_event="check_suite")

    assert handler.handler(event, None)["statusCode"] == 204
    sfn.start_execution.assert_not_called()
