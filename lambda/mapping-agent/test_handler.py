"""Tests for mapping-agent's handler.

No AWS or Anthropic calls: S3, DynamoDB and the client are mocked, and the
corpus is built inline rather than read from corpus/ -- CI runs each suite
from its own directory, and a test that reached across the repo would pass
or fail on edits to a file it does not own.

What is worth pinning here is narrower than what the handler does. This
component's whole reason for existing is that **an LLM may not invent a
control_id** (spec §8.1): the candidate set is looked up deterministically
from rule_mappings.json, the model only picks among it, and two checks in
code refuse an answer that steps outside. Those checks, and the decision to
leave an unmappable finding alone, are the tests that matter. The rest is
plumbing, and is covered where it has bitten before -- pagination, and the
per-container caches that made a corpus change invisible until the Lambda
was recycled.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import handler


FRAMEWORK_FILE = {
    "framework": "CIS-AWS-1.4",
    "framework_name": "CIS Amazon Web Services Foundations Benchmark v1.4.0",
    "source": "https://www.cisecurity.org/benchmark/amazon_web_services",
    "controls": [
        {"control_id": "5.2", "title": "No ingress from 0.0.0.0/0 to remote server administration ports",
         "text": "Security groups should not allow unrestricted ingress to port 22 or 3389."},
        {"control_id": "2.1.1", "title": "S3 buckets employ encryption at rest",
         "text": "Server-side encryption should be enabled on every bucket."},
    ],
}

OWASP_FILE = {
    "framework": "OWASP-CloudNative",
    "controls": [
        {"control_id": "CNAS-6", "title": "Network access controls default to deny",
         "text": "Network access controls should default to deny."},
    ],
}


@pytest.fixture(autouse=True)
def reset_module_caches():
    """The corpus caches are module-level and live for a container's
    lifetime, so without this a mapping loaded by one test would still be
    there for the next -- and a test could pass because of what another
    test fetched."""
    handler._rule_mappings = None
    handler._framework_cache = {}
    handler._anthropic_client = None
    yield
    handler._rule_mappings = None
    handler._framework_cache = {}
    handler._anthropic_client = None


def _finding(finding_id="f1", rule_id="CKV_AWS_24", source="checkov", file="main.tf"):
    return {
        "pk": "PR#pr-1", "sk": f"FINDING#{finding_id}", "finding_id": finding_id,
        "source": source, "rule_id": rule_id, "file": file,
        "severity": "HIGH", "status": "raw",
        "target_type": "terraform", "finding_class": "misconfiguration",
    }


def _body(payload):
    """S3's get_object shape."""
    return {"Body": SimpleNamespace(read=lambda: json.dumps(payload).encode())}


def _s3_corpus(mock_s3, mappings):
    """Serve rule_mappings.json and the framework files by key."""
    files = {
        "corpus/rule_mappings.json": {"mappings": mappings},
        "corpus/frameworks/cis-aws-1.4.json": FRAMEWORK_FILE,
        "corpus/frameworks/owasp-cloud-native.json": OWASP_FILE,
    }
    mock_s3.get_object.side_effect = lambda Bucket, Key: _body(files[Key])


def _model_reply(payload):
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(payload))])


def _mapping(finding_id="f1", framework="CIS-AWS-1.4", control_id="5.2",
             citation="unrestricted ingress to port 22", rationale="CKV_AWS_24 opens 22."):
    return {"finding_id": finding_id, "framework": framework, "control_id": control_id,
            "citation": citation, "rationale": rationale}


def _run(mock_dynamodb, mock_s3, mock_client, findings, mappings, replies):
    """Drive handler() over `findings` with a canned corpus and model."""
    table = MagicMock()
    table.query.return_value = {"Items": findings}
    mock_dynamodb.Table.return_value = table
    _s3_corpus(mock_s3, mappings)
    create = mock_client.return_value.messages.create
    create.side_effect = [_model_reply(r) for r in replies]
    result = handler.handler({"pr_id": "pr-1"}, None)
    return result, table, create


# ---------- the candidate set is the whole point ----------

@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_finding_is_mapped_to_a_control_from_its_candidate_set(
    mock_dynamodb, mock_s3, mock_client
):
    """The happy path, and the shape everything else is measured against:
    the rule is looked up in rule_mappings.json, the control's text is
    fetched, the model picks, and the record carries the citation plus the
    S3 key the text came from."""
    result, table, create = _run(
        mock_dynamodb, mock_s3, mock_client,
        findings=[_finding()],
        mappings={"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]},
        replies=[_mapping()],
    )

    assert result == {
        "pr_id": "pr-1", "mapped_count": 1, "skipped_count": 0, "error_count": 0, "files": ["main.tf"],
    }
    written = table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert written[":status"] == "mapped"
    [cm] = written[":cm"]
    assert cm["framework"] == "CIS-AWS-1.4"
    assert cm["control_id"] == "5.2"
    assert cm["citation_span"] == "unrestricted ingress to port 22"
    # Provenance: which corpus file the cited text came from.
    assert cm["control_text_ref"] == "corpus/frameworks/cis-aws-1.4.json"
    assert cm["rationale"]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_the_model_is_shown_only_the_candidates_and_their_text(
    mock_dynamodb, mock_s3, mock_client
):
    """It picks among controls, it does not recall them. The prompt carries
    each candidate's id and text, and nothing about the control it is not
    being offered."""
    _, _, create = _run(
        mock_dynamodb, mock_s3, mock_client,
        findings=[_finding()],
        mappings={"checkov:CKV_AWS_24": [
            {"framework": "CIS-AWS-1.4", "control_id": "5.2"},
            {"framework": "OWASP-CloudNative", "control_id": "CNAS-6"},
        ]},
        replies=[_mapping()],
    )

    prompt = create.call_args.kwargs["messages"][0]["content"]
    assert "control_id: 5.2" in prompt
    assert "Security groups should not allow unrestricted ingress" in prompt
    assert "control_id: CNAS-6" in prompt
    assert "Network access controls should default to deny." in prompt
    # The other control in the same framework file was never offered.
    assert "2.1.1" not in prompt
    assert "pick exactly one" in prompt


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_control_outside_the_candidate_set_is_refused(
    mock_dynamodb, mock_s3, mock_client
):
    """The guard this component exists for. A control_id that is real, and
    even present in the same corpus file, is still refused when it was not
    among the candidates -- otherwise the deterministic lookup would be a
    suggestion and §8.1's admission rule would rest on the model."""
    result, table, _ = _run(
        mock_dynamodb, mock_s3, mock_client,
        findings=[_finding()],
        mappings={"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]},
        replies=[_mapping(control_id="2.1.1")],
    )

    assert result["mapped_count"] == 0
    assert result["skipped_count"] == 1
    table.update_item.assert_not_called()


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_an_answer_about_a_different_finding_is_refused(
    mock_dynamodb, mock_s3, mock_client
):
    """finding_id is echoed back so a reply can be matched to its question.
    A mismatch means the answer is about something else, and writing it
    would attach one finding's reasoning to another's record."""
    result, table, _ = _run(
        mock_dynamodb, mock_s3, mock_client,
        findings=[_finding("f1")],
        mappings={"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]},
        replies=[_mapping(finding_id="f2")],
    )

    assert (result["mapped_count"], result["skipped_count"]) == (0, 1)
    table.update_item.assert_not_called()


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_reply_with_no_text_block_is_skipped_not_guessed(
    mock_dynamodb, mock_s3, mock_client
):
    table = MagicMock()
    table.query.return_value = {"Items": [_finding()]}
    mock_dynamodb.Table.return_value = table
    _s3_corpus(mock_s3, {"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]})
    mock_client.return_value.messages.create.return_value = SimpleNamespace(content=[])

    result = handler.handler({"pr_id": "pr-1"}, None)

    assert (result["mapped_count"], result["skipped_count"]) == (0, 1)
    table.update_item.assert_not_called()


# ---------- a finding with no candidate is left alone ----------

@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_rule_with_no_mapping_stays_raw_and_costs_no_model_call(
    mock_dynamodb, mock_s3, mock_client
):
    """Coverage is grown by extending rule_mappings.json, never by letting
    the agent choose freely. The finding keeps status raw, so remediation --
    which only touches `mapped` -- never sees it. That is also the filter
    holding back Kubernetes volume today (docs/multi-iac-spec.md §5), by
    absence rather than by design."""
    result, table, create = _run(
        mock_dynamodb, mock_s3, mock_client,
        findings=[_finding(rule_id="CKV_AWS_999")],
        mappings={"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]},
        replies=[],
    )

    assert (result["mapped_count"], result["skipped_count"]) == (0, 1)
    create.assert_not_called()
    table.update_item.assert_not_called()


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_the_lookup_key_is_source_and_rule_id_together(
    mock_dynamodb, mock_s3, mock_client
):
    """Both scanners have their own id space and they overlap in meaning,
    never in spelling. A mapping keyed for checkov must not answer for the
    same rule_id arriving from trivy."""
    result, _, create = _run(
        mock_dynamodb, mock_s3, mock_client,
        findings=[_finding(source="trivy", rule_id="CKV_AWS_24")],
        mappings={"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]},
        replies=[],
    )

    assert result["skipped_count"] == 1
    create.assert_not_called()


# ---------- what the pipeline reads back ----------

@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_files_lists_each_mapped_file_once_for_the_map_state(
    mock_dynamodb, mock_s3, mock_client
):
    """terraform/step_functions.tf fans remediation out over this list, one
    iteration per file. A file appears once however many of its findings
    mapped, and a file whose findings all skipped does not appear."""
    mappings = {"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]}
    result, _, _ = _run(
        mock_dynamodb, mock_s3, mock_client,
        findings=[
            _finding("f1", file="b.tf"),
            _finding("f2", file="a.tf"),
            _finding("f3", file="b.tf"),
            _finding("f4", file="unmapped.tf", rule_id="CKV_AWS_999"),
        ],
        mappings=mappings,
        replies=[_mapping("f1"), _mapping("f2"), _mapping("f3")],
    )

    assert result["files"] == ["a.tf", "b.tf"]
    assert (result["mapped_count"], result["skipped_count"]) == (3, 1)


# ---------- one finding's fault is not the run's ----------
#
# Until 2026-09-18 the loop had no try/except, so the first exception --
# whatever raised it -- ended the invocation with every later finding still
# raw and the pipeline execution failed. remediation-agent had isolated
# per-finding failures from the start; this brings mapping-agent level.

@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_corpus_reference_that_does_not_resolve_fails_only_its_finding(
    mock_dynamodb, mock_s3, mock_client
):
    """The fault corpus/test_corpus.py exists to catch at commit time. If
    it reaches runtime anyway -- an edit that skipped CI, a stale sync --
    the findings on that rule are counted as errors and the others map.
    A framework the handler does not know is a KeyError; a control_id the
    file does not hold is a StopIteration out of next(). Both are faults,
    neither is a decision, so neither is `skipped`."""
    result, table, _ = _run(
        mock_dynamodb, mock_s3, mock_client,
        findings=[
            _finding("f1", rule_id="CKV_AWS_24"),   # fine
            _finding("f2", rule_id="CKV_AWS_18"),   # framework not in _FRAMEWORK_FILES
            _finding("f3", rule_id="CKV_AWS_19"),   # control_id not in the file
            _finding("f4", rule_id="CKV_AWS_24"),   # fine, and after the faults
        ],
        mappings={
            "checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}],
            "checkov:CKV_AWS_18": [{"framework": "CIS-Azure-2.0", "control_id": "1.1"}],
            "checkov:CKV_AWS_19": [{"framework": "CIS-AWS-1.4", "control_id": "9.99"}],
        },
        replies=[_mapping("f1"), _mapping("f4")],
    )

    assert (result["mapped_count"], result["skipped_count"], result["error_count"]) == (2, 0, 2)
    written = [c.kwargs["Key"]["sk"] for c in table.update_item.call_args_list]
    assert written == ["FINDING#f1", "FINDING#f4"]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_an_api_error_on_one_finding_leaves_the_rest_to_map(
    mock_dynamodb, mock_s3, mock_client
):
    """The likelier fault in practice: a rate limit or a 5xx on one call.
    The finding stays raw for the next run; nothing else about the PR is
    lost to it."""
    table = MagicMock()
    table.query.return_value = {"Items": [_finding("f1"), _finding("f2"), _finding("f3")]}
    mock_dynamodb.Table.return_value = table
    _s3_corpus(mock_s3, {"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]})
    mock_client.return_value.messages.create.side_effect = [
        _model_reply(_mapping("f1")),
        RuntimeError("529 overloaded"),
        _model_reply(_mapping("f3")),
    ]

    result = handler.handler({"pr_id": "pr-1"}, None)

    assert (result["mapped_count"], result["error_count"]) == (2, 1)
    assert result["files"] == ["main.tf"]
    written = [c.kwargs["Key"]["sk"] for c in table.update_item.call_args_list]
    assert written == ["FINDING#f1", "FINDING#f3"]


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_a_failed_write_is_an_error_not_a_mapping(
    mock_dynamodb, mock_s3, mock_client
):
    """The model answered and the answer was refused by nothing, but the
    record was not updated -- so it must not be counted as mapped, and its
    file must not be handed to the Map state as if it had findings to
    remediate. The write is the last step precisely so this holds."""
    table = MagicMock()
    table.query.return_value = {"Items": [_finding("f1", file="a.tf"), _finding("f2", file="b.tf")]}
    table.update_item.side_effect = [RuntimeError("ProvisionedThroughputExceeded"), None]
    mock_dynamodb.Table.return_value = table
    _s3_corpus(mock_s3, {"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]})
    mock_client.return_value.messages.create.side_effect = [
        _model_reply(_mapping("f1")), _model_reply(_mapping("f2")),
    ]

    result = handler.handler({"pr_id": "pr-1"}, None)

    assert (result["mapped_count"], result["error_count"]) == (1, 1)
    assert result["files"] == ["b.tf"]


# ---------- plumbing that has bitten before ----------

@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_the_raw_finding_query_pages_to_exhaustion(mock_dynamodb, mock_s3):
    """A Query caps at 1MB of read items and applies the status filter only
    afterwards, so one page can return few or no matches with more behind a
    continuation token. Stopping at the first page would silently leave
    findings unmapped on a large PR."""
    table = MagicMock()
    table.query.side_effect = [
        {"Items": [_finding("f1")], "LastEvaluatedKey": {"pk": "PR#pr-1", "sk": "FINDING#f1"}},
        {"Items": [_finding("f2")]},
    ]
    mock_dynamodb.Table.return_value = table

    assert [f["finding_id"] for f in handler._query_raw_findings("pr-1")] == ["f1", "f2"]
    assert table.query.call_count == 2


@patch.object(handler, "s3")
def test_the_corpus_is_fetched_once_per_container(mock_s3):
    """Both caches live for the container's lifetime. That is deliberate --
    the corpus does not change mid-invocation -- and it is also why syncing
    corpus/ is not enough to change behaviour: the first run after the Trivy
    swap mapped nothing on the new ids until the warm containers were
    recycled (spec §8.2 item 6)."""
    _s3_corpus(mock_s3, {"checkov:CKV_AWS_24": [{"framework": "CIS-AWS-1.4", "control_id": "5.2"}]})

    handler._load_rule_mappings()
    handler._load_rule_mappings()
    handler._load_control("CIS-AWS-1.4", "5.2")
    handler._load_control("CIS-AWS-1.4", "2.1.1")

    fetched = [c.kwargs["Key"] for c in mock_s3.get_object.call_args_list]
    assert fetched == ["corpus/rule_mappings.json", "corpus/frameworks/cis-aws-1.4.json"]


@patch.object(handler, "s3")
def test_a_control_carries_the_key_its_text_came_from(mock_s3):
    _s3_corpus(mock_s3, {})

    control = handler._load_control("OWASP-CloudNative", "CNAS-6")

    assert control["s3_key"] == "corpus/frameworks/owasp-cloud-native.json"
    assert control["title"] == "Network access controls default to deny"
    assert control["text"].startswith("Network access controls")
