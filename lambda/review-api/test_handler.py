"""Tests for review-api's handler. DynamoDB is mocked -- no AWS calls."""

import decimal
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import handler


# The identity API Gateway's JWT authorizer hands the function once it has
# verified the token. Tests default to a signed-in reviewer because that is the
# only way a request reaches the handler in deployed form.
SIGNED_IN = {"sub": "user-uuid-1", "email": "konrad@example.com"}


def _event(route_key, path_params=None, body=None, claims=SIGNED_IN):
    event = {
        "routeKey": route_key,
        "pathParameters": path_params or {},
        "body": json.dumps(body) if body is not None else None,
        "requestContext": {},
    }
    if claims is not None:
        event["requestContext"]["authorizer"] = {"jwt": {"claims": claims}}
    return event


def _body(response):
    return json.loads(response["body"])


# What the fix in FINDING was drafted against: its diff is "-old / +new", so
# the pristine file is "old" and the agent's corrected file is "new".
BASE_CONTENT = "old\n"


@pytest.fixture
def mock_table():
    with patch.object(handler, "dynamodb") as mock_dynamodb, \
            patch.object(handler, "s3") as mock_s3:
        table = MagicMock()
        # A real empty page, not a bare MagicMock. _query_all pages until
        # LastEvaluatedKey is falsy, and every attribute of a MagicMock is
        # truthy -- an unconfigured query makes it loop forever rather than
        # fail, which hangs the run instead of reporting anything. Tests that
        # care about query results override this.
        table.query.return_value = {"Items": []}
        mock_dynamodb.Table.return_value = table
        # An edit reads the fix's base from S3 to compute the diff, and writes
        # the edited content back. Reachable as handler.s3 inside a test.
        mock_s3.get_object.return_value = {"Body": _body_of(BASE_CONTENT)}
        mock_s3.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})
        yield table


def _body_of(text):
    from types import SimpleNamespace
    return SimpleNamespace(read=lambda: text.encode("utf-8"))


FINDING = {
    "pk": "PR#manual-1",
    "sk": "FINDING#abc123",
    "finding_id": "abc123",
    "source": "tfsec",
    "rule_id": "aws-s3-enable-bucket-encryption",
    "file": "main.tf",
    # DynamoDB hands numbers back as Decimal -- the encoder must cope.
    "line_range": [decimal.Decimal(1), decimal.Decimal(3)],
    "status": "fix-proposed",
    "proposed_fix": {
        "diff": "--- a/main.tf\n+++ b/main.tf\n@@ -1,1 +1,1 @@\n-old\n+new\n",
        "rationale": "adds encryption",
        "self_check_passed": True,
        "self_check_new_findings": [],
        "cleared": True,
    },
}

# A finding the pipeline hasn't produced a fix for yet -- nothing to approve
# or edit.
FINDING_NO_FIX = {**FINDING, "status": "mapped", "proposed_fix": None}


# ---------- fix-chain scaffolding (docs/fix-chain-review-spec.md) ----------

# The prerequisite: an earlier fix to the same file. PREREQ_HASH is what a
# dependent drafted on top of it records.
PREREQ_DIFF = "--- a/main.tf\n+++ b/main.tf\n@@ -1,1 +1,1 @@\n-old\n+first fix\n"
PREREQ = {
    **FINDING,
    "sk": "FINDING#earlier1",
    "finding_id": "earlier1",
    "proposed_fix": {**FINDING["proposed_fix"], "diff": PREREQ_DIFF},
}
PREREQ_HASH = hashlib.sha256(PREREQ_DIFF.encode("utf-8")).hexdigest()


def _dependent(applies_after):
    return {
        **FINDING,
        "proposed_fix": {**FINDING["proposed_fix"], "applies_after": applies_after},
    }


def _event_item(action, timestamp):
    return {"sk": f"EVENT#{timestamp}", "action": action, "actor": "someone"}


def _chain(mock_table, dependent, prerequisite, events):
    """Wire the mock so the dependent is fetched first, then its prerequisite,
    and the prerequisite's audit trail reads back as `events`."""
    mock_table.get_item.side_effect = [{"Item": dependent}, {"Item": prerequisite}]
    mock_table.query.return_value = {"Items": events}


def _review(action, **extra):
    body = {"action": action, **extra}
    return _event(
        "POST /prs/{pr_id}/findings/{finding_id}/review",
        {"pr_id": "manual-1", "finding_id": "abc123"},
        body,
    )


def _emf_lines(captured_out):
    """Every EMF record in stdout, parsed, with the shape CloudWatch requires
    checked: an _aws block whose metric names and dimension keys all exist as
    top-level fields. A record that fails this is silently ignored by
    CloudWatch, which is the failure mode a test has to catch."""
    records = []
    for line in captured_out.splitlines():
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if "_aws" not in rec:
            continue
        aws = rec["_aws"]
        assert isinstance(aws["Timestamp"], int)
        for block in aws["CloudWatchMetrics"]:
            assert block["Namespace"] == "IaCPosture"
            for dim_set in block["Dimensions"]:
                for key in dim_set:
                    assert key in rec, f"dimension {key} has no value"
            for m in block["Metrics"]:
                assert m["Name"] in rec, f"metric {m['Name']} has no value"
                assert isinstance(rec[m["Name"]], (int, float))
        records.append(rec)
    return records


# ---------- reads ----------

def test_list_findings_returns_the_prs_findings(mock_table):
    mock_table.query.return_value = {"Items": [FINDING]}

    response = handler.handler(_event("GET /prs/{pr_id}/findings", {"pr_id": "manual-1"}), None)

    assert response["statusCode"] == 200
    payload = _body(response)
    assert payload["count"] == 1
    # Decimals survived serialization as plain ints.
    assert payload["findings"][0]["line_range"] == [1, 3]


def test_get_finding_404s_when_absent(mock_table):
    mock_table.get_item.return_value = {}

    response = handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}", {"pr_id": "manual-1", "finding_id": "nope"}), None
    )

    assert response["statusCode"] == 404


def test_list_events_reads_the_finding_partition_scoped_to_its_pr(mock_table):
    mock_table.query.return_value = {"Items": []}

    handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}/events", {"pr_id": "manual-1", "finding_id": "abc123"}),
        None,
    )

    values = mock_table.query.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":pk"] == "PR#manual-1#FINDING#abc123"
    assert values[":sk_prefix"] == "EVENT#"


def test_audit_trails_do_not_bleed_between_prs_sharing_a_finding_id(mock_table):
    """finding_id is a content hash, so the same rule on the same file yields
    the same id in every PR that scans it. A decision recorded on one PR must
    not appear in another PR's audit trail."""
    mock_table.get_item.return_value = {"Item": FINDING}

    handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "demo-1", "finding_id": "shared-id"},
               {"action": "approved"}),
        None,
    )
    written_pk = mock_table.put_item.call_args.kwargs["Item"]["pk"]

    mock_table.query.return_value = {"Items": []}
    handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}/events",
               {"pr_id": "other-pr", "finding_id": "shared-id"}),
        None,
    )
    read_pk = mock_table.query.call_args.kwargs["ExpressionAttributeValues"][":pk"]

    assert written_pk == "PR#demo-1#FINDING#shared-id"
    assert read_pk != written_pk


def test_unknown_route_404s(mock_table):
    response = handler.handler(_event("DELETE /everything"), None)
    assert response["statusCode"] == 404


# ---------- review decisions ----------

def test_approve_writes_an_audit_event_and_resolves_the_finding(mock_table):
    mock_table.get_item.return_value = {"Item": FINDING}

    response = handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "approved", "notes": "looks right"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["status"] == "resolved"

    event_item = mock_table.put_item.call_args.kwargs["Item"]
    assert event_item["pk"] == "PR#manual-1#FINDING#abc123"
    assert event_item["sk"].startswith("EVENT#")
    assert event_item["actor"] == "konrad@example.com"
    assert event_item["action"] == "approved"

    update_values = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert update_values[":status"] == "resolved"


@pytest.mark.parametrize("action,extra", [
    ("approved", {}),
    ("edited", {"edited_content": "reviewer version\n"}),
    ("rejected", {}),
])
def test_every_recorded_decision_emits_one_review_decisions_metric(mock_table, capsys, action, extra):
    """Spec §7.3's fix-acceptance rate, as raw counts: one metric, the action
    as a dimension, so the rate is metric math over three series rather than
    a fourth thing to keep consistent."""
    mock_table.get_item.return_value = {"Item": FINDING}

    response = handler.handler(_review(action, **extra), None)
    assert response["statusCode"] == 200

    records = _emf_lines(capsys.readouterr().out)
    assert len(records) == 1
    assert records[0]["ReviewDecisions"] == 1
    assert records[0]["Action"] == action
    assert records[0]["finding_id"] == "abc123"


def test_a_blocked_decision_emits_no_metric(mock_table, capsys):
    """A 409 is not a decision. Counting it would inflate the denominator of
    the acceptance rate with attempts that never recorded anything."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [])

    response = handler.handler(_review("approved"), None)
    assert response["statusCode"] == 409

    assert _emf_lines(capsys.readouterr().out) == []


def test_reject_audits_the_decision_and_returns_the_finding_to_human_review(mock_table):
    """Rejecting a proposed fix doesn't make the vulnerability go away -- but
    it does take the fix off the table. Status used to be left wherever it
    was, so a finding approved and later rejected still read "resolved" and
    every consumer that needed the truth had to read the event log instead."""
    mock_table.get_item.return_value = {"Item": FINDING}

    response = handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "rejected"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["status"] == "needs-human-only"
    mock_table.put_item.assert_called_once()
    values = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":status"] == "needs-human-only"


def test_rejecting_an_approved_fix_retracts_resolved(mock_table):
    """The case that used to lie. Approve, then reject: status must now say
    needs-human-only, so it agrees with the event log for the first time."""
    mock_table.get_item.return_value = {"Item": {**FINDING, "status": "resolved"}}

    handler.handler(_review("rejected"), None)

    values = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":status"] == "needs-human-only"


def test_rejecting_a_finding_with_no_fix_moves_nothing(mock_table):
    """There was nothing proposed to refuse. The event is recorded; a mapped
    finding stays mapped so remediation still picks it up."""
    mock_table.get_item.return_value = {"Item": FINDING_NO_FIX}

    response = handler.handler(_review("rejected"), None)

    assert response["statusCode"] == 200
    assert _body(response)["status"] is None
    mock_table.put_item.assert_called_once()
    mock_table.update_item.assert_not_called()


def test_edit_replaces_the_diff_preserves_the_agents_and_voids_the_self_check(mock_table):
    mock_table.get_item.return_value = {"Item": FINDING}

    response = handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "edited", "edited_content": "reviewer edit\n"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["status"] == "resolved"

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    # The reviewer sent a file; the diff against the base is computed here,
    # the same way remediation-agent computes the agent's.
    assert "-old\n" in written["diff"] and "+reviewer edit\n" in written["diff"]
    assert written["diff"].startswith("--- a/main.tf\n+++ b/main.tf\n")
    assert written["agent_diff"].endswith("-old\n+new\n")

    # And the content is now the fix, in the place anything rooted on it reads.
    put = handler.s3.put_object.call_args.kwargs
    assert put["Key"] == "fixes/manual-1/abc123/main.tf"
    assert put["Body"] == b"reviewer edit\n"
    # spec §6's guarantee applies just as much to a human edit: an unscanned
    # diff cannot carry a passing self-check.
    assert written["self_check_passed"] is False
    assert written["self_check_new_findings"] == []
    assert written["cleared"] is False

    event_item = mock_table.put_item.call_args.kwargs["Item"]
    assert "+reviewer edit\n" in event_item["edited_diff"]


def test_an_edit_preserves_what_the_fix_is_drafted_on(mock_table):
    """applies_after is deliberately not in the reset list alongside the
    self-check fields. Those are claims about whether this diff was verified,
    which a hand-edit invalidates. applies_after is a fact about what the diff
    is rooted on, and editing the diff does not re-root it -- the reviewer's
    version still only applies once its prerequisites do."""
    chain = [{"finding_id": "earlier1", "diff_sha256": PREREQ_HASH}]
    _chain(mock_table, _dependent(chain), PREREQ, [_event_item("approved", "2026-01-01")])

    handler.handler(_review("edited", edited_content="reviewer version\n"), None)

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["applies_after"] == chain
    assert written["self_check_passed"] is False


def test_editing_an_unparseable_fix_clears_the_agents_parse_failure(mock_table):
    """The likeliest response to "the fix did not parse" is a reviewer fixing
    the syntax by hand. Carrying the agent's parse failure onto that edit would
    keep flagging a file that no longer exists as broken -- and scan_errors
    outranks every other badge, so it would mask the edit's real state."""
    unparseable = {
        **FINDING,
        "status": "needs-human-only",
        "proposed_fix": {
            **FINDING["proposed_fix"],
            "self_check_passed": False,
            "cleared": False,
            "scan_errors": ["main.tf"],
        },
    }
    mock_table.get_item.return_value = {"Item": unparseable}

    response = handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "edited", "edited_content": "  }\n"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["scan_errors"] == []
    # Still unverified, just for the ordinary reason now: no scan has run
    # against the reviewer's diff either.
    assert written["self_check_passed"] is False


def test_second_edit_does_not_overwrite_the_agents_original_diff(mock_table):
    already_edited = {
        **FINDING,
        "proposed_fix": {
            "diff": "first edit",
            "agent_diff": "the agent's original",
            "self_check_passed": False,
            "self_check_new_findings": [],
            "cleared": False,
        },
    }
    mock_table.get_item.return_value = {"Item": already_edited}

    handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "edited", "edited_content": "second edit\n"},
        ),
        None,
    )

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["agent_diff"] == "the agent's original"


def test_edit_without_a_diff_is_rejected(mock_table):
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"}, {"action": "edited"}),
        None,
    )

    assert response["statusCode"] == 400
    mock_table.put_item.assert_not_called()


def test_edited_content_on_a_non_edit_action_is_rejected(mock_table):
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"},
               {"action": "approved", "edited_content": "sneaky\n"}),
        None,
    )

    assert response["statusCode"] == 400
    mock_table.put_item.assert_not_called()


def test_edited_diff_is_refused_outright(mock_table):
    """Not deprecated, refused. A reviewer-authored diff was never validated
    against anything; the contract is the corrected file, and this side
    computes the diff."""
    response = handler.handler(_review("edited", edited_diff="--- a/main.tf\n+x\n"), None)

    assert response["statusCode"] == 400
    assert "edited_content" in _body(response)["error"]
    mock_table.put_item.assert_not_called()


def test_an_edit_that_changes_nothing_is_refused(mock_table):
    """Identical to the base means no diff, and a fix with no diff is not a
    fix. Nothing is written, including to S3."""
    mock_table.get_item.return_value = {"Item": FINDING}

    response = handler.handler(_review("edited", edited_content=BASE_CONTENT), None)

    assert response["statusCode"] == 400
    mock_table.put_item.assert_not_called()
    handler.s3.put_object.assert_not_called()


def test_an_edit_on_a_chained_fix_diffs_against_its_prerequisites_output(mock_table):
    """The base for a fix with prerequisites is the last prerequisite's
    corrected file, not the pristine snapshot -- applies_after is cumulative,
    so that one file already has every earlier fix applied."""
    # A satisfied prerequisite, so the edit is not blocked and reaches the diff.
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [_event_item("approved", "2026-01-01")])
    handler.s3.get_object.return_value = {"Body": _body_of("after earlier1\n")}

    response = handler.handler(_review("edited", edited_content="after earlier1\nplus mine\n"), None)
    assert response["statusCode"] == 200, _body(response)

    read_key = handler.s3.get_object.call_args.kwargs["Key"]
    assert read_key == "fixes/manual-1/earlier1/main.tf"
    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert "+plus mine\n" in written["diff"]
    # Purely additive against that base: nothing the prerequisite wrote is
    # re-proposed or removed, which is what "the right base" looks like.
    removed = [l for l in written["diff"].splitlines()
               if l.startswith("-") and not l.startswith("---")]
    assert removed == []


def test_get_content_returns_the_fixes_corrected_file(mock_table):
    mock_table.get_item.return_value = {"Item": FINDING}
    handler.s3.get_object.return_value = {"Body": _body_of("new\n")}

    response = handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}/content",
               {"pr_id": "manual-1", "finding_id": "abc123"}),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response) == {"finding_id": "abc123", "file": "main.tf", "content": "new\n"}
    assert handler.s3.get_object.call_args.kwargs["Key"] == "fixes/manual-1/abc123/main.tf"


def test_get_content_404s_when_the_fix_has_no_stored_file(mock_table):
    mock_table.get_item.return_value = {"Item": FINDING}
    handler.s3.get_object.side_effect = handler.s3.exceptions.NoSuchKey()

    response = handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}/content",
               {"pr_id": "manual-1", "finding_id": "abc123"}),
        None,
    )

    assert response["statusCode"] == 404


@pytest.mark.parametrize("action", ["approved", "edited"])
def test_approve_or_edit_without_a_proposed_fix_is_a_conflict(mock_table, action):
    mock_table.get_item.return_value = {"Item": FINDING_NO_FIX}

    body = {"action": action}
    if action == "edited":
        body["edited_content"] = "would-be edit\n"

    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"}, body),
        None,
    )

    assert response["statusCode"] == 409
    mock_table.put_item.assert_not_called()


def test_self_check_passed_in_the_request_body_is_ignored(mock_table):
    """The client can send whatever it likes -- only the server-computed value
    on an edit (always False) ends up written."""
    mock_table.get_item.return_value = {"Item": FINDING}

    handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "edited", "edited_content": "x\n", "self_check_passed": True},
        ),
        None,
    )

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["self_check_passed"] is False


@pytest.mark.parametrize("body,expected_fragment", [
    ({"action": "yolo"}, "action must be one of"),
    ({}, "action must be one of"),
])
def test_review_rejects_bad_input_without_writing(mock_table, body, expected_fragment):
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"}, body),
        None,
    )

    assert response["statusCode"] == 400
    assert expected_fragment in _body(response)["error"]
    mock_table.put_item.assert_not_called()


def test_actor_comes_from_the_token_not_the_request_body(mock_table):
    """The whole point of the authorizer: a caller cannot sign someone else's
    name to a decision by putting it in the body."""
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"},
               {"action": "approved", "actor": "someone-else"}),
        None,
    )

    assert response["statusCode"] == 200
    assert mock_table.put_item.call_args.kwargs["Item"]["actor"] == "konrad@example.com"


def test_review_without_verified_claims_is_rejected(mock_table):
    """Defence in depth: if the authorizer is ever detached from the route, the
    handler refuses rather than recording an unattributable decision."""
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"},
               {"action": "approved"}, claims=None),
        None,
    )

    assert response["statusCode"] == 401
    mock_table.put_item.assert_not_called()
    mock_table.update_item.assert_not_called()


def test_actor_falls_back_to_sub_when_the_token_carries_no_email(mock_table):
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"},
               {"action": "approved"}, claims={"sub": "user-uuid-1"}),
        None,
    )

    assert response["statusCode"] == 200
    assert mock_table.put_item.call_args.kwargs["Item"]["actor"] == "user-uuid-1"


def test_review_on_a_missing_finding_writes_no_orphan_event(mock_table):
    mock_table.get_item.return_value = {}

    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "ghost"},
               {"action": "approved"}),
        None,
    )

    assert response["statusCode"] == 404
    mock_table.put_item.assert_not_called()


# ---------- failure handling ----------

def test_unexpected_error_returns_500_without_leaking_details(mock_table):
    mock_table.query.side_effect = RuntimeError("ProvisionedThroughputExceeded: secret internals")

    response = handler.handler(_event("GET /prs/{pr_id}/findings", {"pr_id": "manual-1"}), None)

    assert response["statusCode"] == 500
    assert _body(response) == {"error": "internal error"}


def test_query_all_follows_pagination(mock_table):
    mock_table.query.side_effect = [
        {"Items": [FINDING], "LastEvaluatedKey": {"pk": "PR#manual-1", "sk": "FINDING#abc123"}},
        {"Items": [{**FINDING, "finding_id": "def456"}]},
    ]

    response = handler.handler(_event("GET /prs/{pr_id}/findings", {"pr_id": "manual-1"}), None)

    assert _body(response)["count"] == 2
    assert mock_table.query.call_count == 2


# ---------- fix-chain enforcement (docs/fix-chain-review-spec.md §3) ----------

SATISFIED = [{"finding_id": "earlier1", "diff_sha256": PREREQ_HASH}]


def _unmet(response):
    return _body(response)["unmet"]


def test_approve_is_blocked_when_the_prerequisite_was_rejected(mock_table):
    """And specifically when that rejection followed an approval, so the
    prerequisite's status is still "resolved". This is the case a status-based
    check gets wrong: rejection deliberately leaves status alone, so status
    reports the stale approval while the standing decision is the rejection."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [
        _event_item("approved", "2026-01-01"),
        _event_item("rejected", "2026-01-02"),
    ])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "rejected"}]
    # A blocked decision is not an attempted decision.
    mock_table.put_item.assert_not_called()
    mock_table.update_item.assert_not_called()


def test_approve_is_blocked_when_the_prerequisite_has_no_events(mock_table):
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "undecided"}]
    mock_table.put_item.assert_not_called()


def test_approve_is_blocked_when_the_entry_carries_no_hash(mock_table):
    """Absent is not the same as fresh, so it fails closed. Covers the records
    written before the chain carried hashes, whose entries are bare id strings."""
    _chain(mock_table, _dependent([{"finding_id": "earlier1"}]), PREREQ,
           [_event_item("approved", "2026-01-01")])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "unverifiable"}]


def test_approve_is_blocked_when_the_prerequisites_diff_changed(mock_table):
    """The prerequisite was edited after this fix was drafted on it, so this
    diff's context describes a file that no longer exists."""
    edited = {
        **PREREQ,
        "proposed_fix": {**PREREQ["proposed_fix"], "diff": "--- a/main.tf\n+reviewer rewrote it\n"},
    }
    _chain(mock_table, _dependent(SATISFIED), edited, [_event_item("edited", "2026-01-01")])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "stale"}]


def test_approve_is_blocked_when_the_prerequisite_is_gone(mock_table):
    mock_table.get_item.side_effect = [{"Item": _dependent(SATISFIED)}, {}]

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "missing"}]


def test_approve_is_allowed_when_the_prerequisite_is_resolved_and_unchanged(mock_table):
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [_event_item("approved", "2026-01-01")])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 200
    assert _body(response)["status"] == "resolved"
    mock_table.put_item.assert_called_once()


def test_an_edited_prerequisite_still_satisfies_if_its_diff_is_unchanged(mock_table):
    """Satisfaction is about the latest action being resolving, and staleness
    is a separate hash question. An edit that happened to leave the diff
    byte-identical blocks nothing."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [_event_item("edited", "2026-01-01")])

    assert handler.handler(_review("approved"), None)["statusCode"] == 200


def test_reject_is_never_blocked_by_an_unmet_prerequisite(mock_table):
    """The reviewer's escape hatch from a bad chain. Rejecting is always safe:
    it records that this fix is refused, which is true regardless of what
    happened upstream of it."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [])

    response = handler.handler(_review("rejected"), None)

    assert response["statusCode"] == 200
    mock_table.put_item.assert_called_once()
    # Not blocked, and the fix is off the table.
    values = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":status"] == "needs-human-only"


def test_edit_is_blocked_on_the_same_terms_as_approve(mock_table):
    """An edit resolves the finding just as an approval does, so it cannot be
    a way around the gate. A reviewer wanting a fix independent of its chain
    rejects it and lets a re-run redraft it."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [_event_item("rejected", "2026-01-01")])

    response = handler.handler(_review("edited", edited_content="reviewer version\n"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "rejected"}]
    mock_table.put_item.assert_not_called()


def test_a_fix_with_an_empty_chain_is_unaffected(mock_table):
    mock_table.get_item.return_value = {"Item": _dependent([])}

    assert handler.handler(_review("approved"), None)["statusCode"] == 200


def test_a_fix_predating_the_chain_field_is_unaffected(mock_table):
    """applies_after is absent entirely on the 15 records written before it
    existed. Absent means "not chained", which is what those records are."""
    mock_table.get_item.return_value = {"Item": FINDING}

    assert handler.handler(_review("approved"), None)["statusCode"] == 200


def test_every_unmet_prerequisite_is_reported_at_once(mock_table):
    """So a reviewer sees the whole blocking set rather than discovering it one
    409 at a time."""
    second = {**PREREQ, "sk": "FINDING#earlier2", "finding_id": "earlier2"}
    chain = [
        {"finding_id": "earlier1", "diff_sha256": PREREQ_HASH},
        {"finding_id": "earlier2", "diff_sha256": "a stale hash"},
    ]
    mock_table.get_item.side_effect = [
        {"Item": _dependent(chain)}, {"Item": PREREQ}, {"Item": second},
    ]
    mock_table.query.side_effect = [
        {"Items": [_event_item("rejected", "2026-01-01")]},
        {"Items": [_event_item("approved", "2026-01-01")]},
    ]

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [
        {"finding_id": "earlier1", "reason": "rejected"},
        {"finding_id": "earlier2", "reason": "stale"},
    ]


def test_a_superseded_finding_is_refused_by_the_existing_no_fix_check(mock_table):
    """It has no fix of its own, so it is not a chain link in either direction
    -- the decision belongs on the fix that superseded it."""
    mock_table.get_item.return_value = {
        "Item": {**FINDING, "status": "superseded", "superseded_by": "earlier1",
                 "proposed_fix": None},
    }

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _body(response)["error"] == "finding has no proposed fix to act on"


# ---------- cascade on edit (docs/fix-chain-review-spec.md §4) ----------

# A fix drafted on top of FINDING, already accepted by a human.
DEPENDENT = {
    **FINDING,
    "sk": "FINDING#dependent1",
    "finding_id": "dependent1",
    "status": "resolved",
    "proposed_fix": {
        **FINDING["proposed_fix"],
        "applies_after": [{"finding_id": "abc123", "diff_sha256": "whatever-it-was"}],
    },
}


def _updates_for(mock_table, finding_id):
    return [
        call for call in mock_table.update_item.call_args_list
        if call.kwargs["Key"]["sk"] == f"FINDING#{finding_id}"
    ]


def test_editing_a_fix_reopens_the_dependents_drafted_on_it(mock_table):
    """Section 3 blocks a dependent at review time. It does nothing for one
    already approved, because that decision has happened -- so an edit has to
    reach forward and reopen it, or the approved set is quietly unassemblable."""
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, DEPENDENT]}

    response = handler.handler(_review("edited", edited_content="reviewer version\n"), None)

    assert response["statusCode"] == 200
    assert _body(response)["reopened_dependents"] == ["dependent1"]

    reopened = _updates_for(mock_table, "dependent1")
    assert len(reopened) == 1
    values = reopened[0].kwargs["ExpressionAttributeValues"]
    # mapped, not needs-human-only: nothing a human can do with it until it is
    # redrafted, and mapped is what the redraft picks up.
    assert values[":status"] == "mapped"
    assert "abc123" in values[":reason"]

    # A machine reopening a human's decision has to be on the record.
    system_events = [
        call.kwargs["Item"] for call in mock_table.put_item.call_args_list
        if call.kwargs["Item"]["actor"] == "system"
    ]
    assert len(system_events) == 1
    assert system_events[0]["pk"] == "PR#manual-1#FINDING#dependent1"
    assert system_events[0]["action"] == "reopened"


def test_rejecting_a_fix_reopens_the_dependents_drafted_on_it(mock_table):
    """The other way a base stops being real. An edit changes it; a rejection
    means it is never landing. Approve f1, approve f2, reject f1 left f2
    resolved and unassemblable, with nothing reaching forward to say so."""
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, DEPENDENT]}

    response = handler.handler(_review("rejected"), None)

    assert response["statusCode"] == 200
    assert _body(response)["reopened_dependents"] == ["dependent1"]

    values = _updates_for(mock_table, "dependent1")[0].kwargs["ExpressionAttributeValues"]
    assert values[":status"] == "mapped"
    assert "rejected" in values[":reason"]
    # The remedy differs from the edit case and the reason has to say so.
    assert "never landing" in values[":reason"]

    system_events = [
        call.kwargs["Item"] for call in mock_table.put_item.call_args_list
        if call.kwargs["Item"]["actor"] == "system"
    ]
    assert len(system_events) == 1
    assert system_events[0]["action"] == "reopened"


SUPERSEDED = {
    **FINDING,
    "sk": "FINDING#shadowed1",
    "finding_id": "shadowed1",
    "rule_id": "aws-s3-block-public-acls",
    "status": "superseded",
    "superseded_by": "abc123",
    "proposed_fix": None,
}


@pytest.mark.parametrize("action,kwargs", [
    ("edited", {"edited_content": "reviewer version\n"}),
    ("rejected", {}),
])
def test_changing_a_fix_returns_the_findings_it_superseded_to_mapped(mock_table, action, kwargs):
    """A superseded finding never had a fix of its own: this one cleared its
    rule as a side effect. After an edit that may no longer be so; after a
    rejection it certainly is not. It goes back to mapped -- not
    needs-human-only, because there is no proposal to review -- so the next
    remediation run drafts it a fix for the first time. superseded_by is
    stored precisely so this reversal can find it."""
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, SUPERSEDED]}

    response = handler.handler(_review(action, **kwargs), None)

    assert response["statusCode"] == 200
    assert _body(response)["reopened_dependents"] == ["shadowed1"]

    update = _updates_for(mock_table, "shadowed1")[0].kwargs
    assert update["ExpressionAttributeValues"][":status"] == "mapped"
    assert "REMOVE superseded_by" in update["UpdateExpression"]
    # No proposed_fix to hang a stale_reason on; the event carries the why.
    assert "stale_reason" not in update["UpdateExpression"]

    system_events = [
        call.kwargs["Item"] for call in mock_table.put_item.call_args_list
        if call.kwargs["Item"]["actor"] == "system"
    ]
    assert len(system_events) == 1
    assert system_events[0]["pk"] == "PR#manual-1#FINDING#shadowed1"
    assert "abc123" in system_events[0]["notes"]


def test_reopening_a_chain_dependent_also_reopens_what_it_superseded(mock_table):
    """f1 is edited; f2 (drafted on f1) is reopened for redrafting. s3 was
    superseded by f2's *old* draft. The redraft is a new draft and the claim
    that it clears s3 has to be re-earned, so s3 goes back to mapped too.
    Observed live before this existed: s3 stayed superseded, pointing at a
    diff that no longer existed."""
    superseded_by_dependent = {
        **SUPERSEDED,
        "sk": "FINDING#shadowed2",
        "finding_id": "shadowed2",
        "superseded_by": "dependent1",
    }
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, DEPENDENT, superseded_by_dependent]}

    response = handler.handler(_review("edited", edited_content="reviewer version\n"), None)

    assert response["statusCode"] == 200
    assert set(_body(response)["reopened_dependents"]) == {"dependent1", "shadowed2"}

    update = _updates_for(mock_table, "shadowed2")[0].kwargs
    assert update["ExpressionAttributeValues"][":status"] == "mapped"
    assert "REMOVE superseded_by" in update["UpdateExpression"]

    # The event names the fix that actually superseded it, not the one edited.
    event = next(c.kwargs["Item"] for c in mock_table.put_item.call_args_list
                 if c.kwargs["Item"].get("finding_id") == "shadowed2")
    assert "dependent1" in event["notes"] and "redrafted" in event["notes"]


def test_a_finding_superseded_by_an_unrelated_fix_is_not_reopened(mock_table):
    """Only one hop: supersede is not transitive, and a finding superseded by
    something outside the changed fix's chain has no reason to move."""
    unrelated = {**SUPERSEDED, "sk": "FINDING#shadowed3", "finding_id": "shadowed3",
                 "superseded_by": "someone-else"}
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, unrelated]}

    response = handler.handler(_review("edited", edited_content="reviewer version\n"), None)

    assert _body(response)["reopened_dependents"] == []
    assert _updates_for(mock_table, "shadowed3") == []


def test_approve_is_blocked_with_reason_reopened_not_rejected(mock_table):
    """A reopened prerequisite is the system's doing, and the remedy differs:
    a rejected one is dropped from the chain, a reopened one is waiting to be
    redrafted and re-reviewed. Reporting it as "rejected" would send the
    reviewer to the wrong fix."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [
        _event_item("approved", "2026-01-01"),
        {"sk": "EVENT#2026-01-02#system", "action": "reopened", "actor": "system"},
    ])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "reopened"}]


def test_the_two_lambdas_hash_a_diff_identically():
    """review-api compares the hash remediation-agent recorded. They are
    separate deployables with no shared module, so the helper is duplicated
    and a comment says it must stay identical. This is that comment,
    enforced."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "remediation_handler",
        Path(__file__).parents[1] / "remediation-agent" / "handler.py",
    )
    remediation = importlib.util.module_from_spec(spec)
    with patch.dict("sys.modules", {"anthropic": MagicMock()}):
        spec.loader.exec_module(remediation)

    diff = "--- a/main.tf\n+++ b/main.tf\n@@ -1 +1 @@\n-old\n+new\n"
    assert handler._diff_sha256(diff) == remediation._diff_sha256(diff)


def test_a_finding_with_no_dependents_is_untouched_by_an_edit(mock_table):
    unrelated = {**FINDING, "sk": "FINDING#other", "finding_id": "other"}
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, unrelated]}

    response = handler.handler(_review("edited", edited_content="reviewer version\n"), None)

    assert _body(response)["reopened_dependents"] == []
    assert _updates_for(mock_table, "other") == []
    # Only the reviewer's own event was written.
    mock_table.put_item.assert_called_once()
    assert mock_table.put_item.call_args.kwargs["Item"]["actor"] == "konrad@example.com"


def test_approving_a_fix_does_not_cascade(mock_table):
    """Only an edit changes the diff, and it is the diff dependents were
    drafted against. An approval leaves it exactly as it was."""
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, DEPENDENT]}

    response = handler.handler(_review("approved"), None)

    assert _body(response)["reopened_dependents"] == []
    assert _updates_for(mock_table, "dependent1") == []


def test_the_cascade_skips_the_finding_being_edited(mock_table):
    """A fix naming itself would otherwise reopen the very finding the
    reviewer just resolved."""
    self_referential = {
        **FINDING,
        "proposed_fix": {
            **FINDING["proposed_fix"],
            "applies_after": [{"finding_id": "abc123", "diff_sha256": PREREQ_HASH}],
        },
    }
    mock_table.get_item.side_effect = [{"Item": self_referential}, {"Item": PREREQ}]
    mock_table.query.side_effect = [
        {"Items": [_event_item("approved", "2026-01-01")]},
        {"Items": [self_referential]},
    ]

    response = handler.handler(_review("edited", edited_content="reviewer version\n"), None)

    assert _body(response)["reopened_dependents"] == []


def test_a_cascade_event_cannot_collide_with_the_edit_that_caused_it(mock_table):
    """Both carry the same timestamp, and ReviewEvents are keyed on it. Without
    a distinct suffix the cascade would overwrite the reviewer's own event on a
    finding that is both edited and a dependent."""
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [DEPENDENT]}

    handler.handler(_review("edited", edited_content="reviewer version\n"), None)

    sort_keys = [call.kwargs["Item"]["sk"] for call in mock_table.put_item.call_args_list]
    assert len(sort_keys) == len(set(sort_keys))


# ======================================================================
# write-back: the commit plan and commit requests (docs/write-back-spec.md)
# ======================================================================

COMMITTER = {**SIGNED_IN, "cognito:groups": ["committers"]}
META = {"pk": "PR#gh-1-7", "sk": "GITHUB", "repository": "o/r",
        "repository_id": decimal.Decimal(1), "pr_number": decimal.Decimal(7)}
PLANNED = {"file": "main.tf", "outcome": "commit", "reason": None, "tip": "f1", "chain": [],
           "left_out": [], "content": "whole file", "content_sha256": "h1", "diff": "-a\n+b\n"}
CONFIRM = {"confirm": [{"file": "main.tf", "tip": "f1", "content_sha256": "h1"}]}


@pytest.fixture
def write_back():
    """review-api with write-back deployed, a GitHub PR's meta recorded, no
    request in flight, and a preview with one file to commit."""
    with patch.object(handler, "COMMITTER_FUNCTION_NAME", "committer"), \
            patch.object(handler, "_pull_request_meta", return_value=META) as meta, \
            patch.object(handler, "_commit_requests", return_value=[]) as requests, \
            patch.object(handler, "_preview_plan", return_value=[dict(PLANNED)]) as preview, \
            patch.object(handler, "lambda_client") as lambda_client, \
            patch.object(handler, "dynamodb") as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        yield SimpleNamespace(meta=meta, requests=requests, preview=preview,
                              lambda_client=lambda_client, table=table)


def _commit(body=CONFIRM, claims=COMMITTER):
    return handler.handler(_event("POST /prs/{pr_id}/commits", {"pr_id": "gh-1-7"}, body, claims), None)


def test_the_commit_plan_is_a_preview_without_file_content(write_back):
    response = handler.handler(_event("GET /prs/{pr_id}/commit-plan", {"pr_id": "gh-1-7"},
                                      claims=COMMITTER), None)
    body = _body(response)
    assert response["statusCode"] == 200
    assert body["preview"] is True and body["repository"] == "o/r" and body["pr_number"] == 7
    assert body["can_commit"] is True and body["write_back_deployed"] is True
    assert body["counts"] == {"commit": 1, "already": 0, "held": 0}
    assert "content" not in body["files"][0] and body["files"][0]["diff"] == "-a\n+b\n"
    assert body["latest_request"] is None


def test_the_commit_plan_says_a_reviewer_outside_the_group_cannot_commit(write_back):
    body = _body(handler.handler(_event("GET /prs/{pr_id}/commit-plan", {"pr_id": "gh-1-7"}), None))
    assert body["can_commit"] is False


def test_the_commit_plan_names_the_latest_request(write_back):
    write_back.requests.return_value = [{"sk": "COMMIT#01A", "status": "committed"},
                                        {"sk": "COMMIT#01B", "status": "held"}]
    body = _body(handler.handler(_event("GET /prs/{pr_id}/commit-plan", {"pr_id": "gh-1-7"}), None))
    assert body["latest_request"]["sk"] == "COMMIT#01B"


def test_a_pr_github_does_not_know_has_no_commit_plan(write_back):
    write_back.meta.return_value = None
    response = handler.handler(_event("GET /prs/{pr_id}/commit-plan", {"pr_id": "manual-1"}), None)
    assert response["statusCode"] == 404


def test_a_commit_request_is_recorded_under_the_tokens_identity_and_handed_over(write_back):
    response = _commit({**CONFIRM, "requested_by": "someone-else@example.com"})

    assert response["statusCode"] == 202
    request_id = _body(response)["request_id"]
    item = write_back.table.put_item.call_args.kwargs["Item"]
    assert item["sk"] == f"COMMIT#{request_id}" and item["status"] == "requested"
    assert item["requested_by"] == "konrad@example.com"
    assert item["confirmed"] == CONFIRM["confirm"]
    assert write_back.table.put_item.call_args.kwargs["ConditionExpression"] == "attribute_not_exists(sk)"
    invoke = write_back.lambda_client.invoke.call_args.kwargs
    assert invoke["InvocationType"] == "Event" and invoke["FunctionName"] == "committer"
    assert json.loads(invoke["Payload"]) == {"pr_id": "gh-1-7", "request_id": request_id}


@pytest.mark.parametrize("groups", [["committers"], "[committers]", "[reviewers committers]",
                                    "committers"])
def test_the_group_claim_is_read_in_either_shape(write_back, groups):
    # An HTTP API JWT authorizer passes an array claim as "[a b]".
    assert _commit(claims={**SIGNED_IN, "cognito:groups": groups})["statusCode"] == 202


@pytest.mark.parametrize("claims", [SIGNED_IN, {**SIGNED_IN, "cognito:groups": "[reviewers]"},
                                    {**SIGNED_IN, "cognito:groups": "[not-committers]"}])
def test_only_a_committer_may_commit(write_back, claims):
    response = _commit(claims=claims)
    assert response["statusCode"] == 403
    write_back.table.put_item.assert_not_called()
    write_back.lambda_client.invoke.assert_not_called()


def test_a_commit_request_without_verified_claims_is_rejected(write_back):
    assert _commit(claims=None)["statusCode"] == 401


def test_a_commit_request_before_write_back_is_deployed_is_refused(write_back):
    with patch.object(handler, "COMMITTER_FUNCTION_NAME", ""):
        assert _commit()["statusCode"] == 503
    write_back.table.put_item.assert_not_called()


@pytest.mark.parametrize("body", [{}, {"confirm": []}, {"confirm": [{"file": "main.tf"}]},
                                  {"confirm": "main.tf"}])
def test_a_commit_request_must_say_what_was_confirmed(write_back, body):
    assert _commit(body)["statusCode"] == 400


def test_a_second_request_while_one_is_in_flight_is_refused(write_back):
    write_back.requests.return_value = [{"request_id": "01A", "status": "committing"}]
    response = _commit()
    assert response["statusCode"] == 409 and _body(response)["request_id"] == "01A"
    write_back.table.put_item.assert_not_called()


def test_a_plan_that_moved_since_it_was_shown_is_not_committed(write_back):
    # The tip was edited after the preview: same finding id, new content.
    write_back.preview.return_value = [{**PLANNED, "content_sha256": "h2"}]
    response = _commit()
    assert response["statusCode"] == 409 and _body(response)["changed"] == ["main.tf"]
    write_back.table.put_item.assert_not_called()


def test_a_held_file_cannot_be_confirmed_into_a_commit(write_back):
    write_back.preview.return_value = [{**PLANNED, "outcome": "held"}]
    assert _commit()["statusCode"] == 409


def test_a_request_the_committer_never_received_is_marked_failed(write_back):
    write_back.lambda_client.invoke.side_effect = RuntimeError("throttled")
    response = _commit()
    assert response["statusCode"] == 502
    values = write_back.table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":failed"] == "failed"


def test_a_commit_request_is_read_back_by_id(mock_table):
    mock_table.get_item.return_value = {"Item": {"request_id": "01A", "status": "committed"}}
    response = handler.handler(_event("GET /prs/{pr_id}/commits/{request_id}",
                                      {"pr_id": "gh-1-7", "request_id": "01A"}), None)
    assert _body(response)["status"] == "committed"
    assert mock_table.get_item.call_args.kwargs["Key"] == {"pk": "PR#gh-1-7", "sk": "COMMIT#01A"}

    mock_table.get_item.return_value = {}
    response = handler.handler(_event("GET /prs/{pr_id}/commits/{request_id}",
                                      {"pr_id": "gh-1-7", "request_id": "nope"}), None)
    assert response["statusCode"] == 404


def test_the_preview_plans_from_the_event_log_and_the_snapshot(mock_table):
    """The real _preview_plan over a fake table: the latest event decides,
    and the head is the S3 snapshot."""
    head = "a\nb\n"
    approved = {"pk": "PR#gh-1-7", "sk": "FINDING#f1", "finding_id": "f1", "file": "main.tf",
                "rule_id": "R1", "status": "resolved",
                "proposed_fix": {"diff": "d1", "self_check_passed": True, "applies_after": [],
                                 "base_sha256": hashlib.sha256(head.encode()).hexdigest()}}
    retracted = {**approved, "sk": "FINDING#f2", "finding_id": "f2", "file": "other.tf"}
    events = {"f1": [{"sk": "EVENT#1", "action": "approved"}],
              "f2": [{"sk": "EVENT#1", "action": "approved"}, {"sk": "EVENT#2", "action": "rejected"}]}

    def query(**kwargs):
        pk = kwargs["ExpressionAttributeValues"][":pk"]
        if pk == "PR#gh-1-7":
            return {"Items": [approved, retracted]}
        return {"Items": events[pk.rsplit("#", 1)[1]]}

    mock_table.query.side_effect = query
    contents = {"scans/gh-1-7/main.tf": head, "fixes/gh-1-7/f1/main.tf": "a\nB\n"}
    handler.s3.get_object.side_effect = lambda Bucket, Key: {"Body": _body_of(contents[Key])}

    [plan] = handler._preview_plan("gh-1-7")

    assert (plan["file"], plan["outcome"], plan["tip"]) == ("main.tf", "commit", "f1")
    assert plan["content_sha256"] == hashlib.sha256(b"a\nB\n").hexdigest()


def test_ulids_sort_by_time_and_do_not_collide():
    earlier, later = handler._ulid(1_000), handler._ulid(2_000)
    assert len(earlier) == 26 and earlier < later
    assert handler._ulid(1_000) != earlier
