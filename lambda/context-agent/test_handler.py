"""Tests for context-agent's handler.

No AWS or Anthropic calls: S3 and the client are mocked, and the snapshot is
a temp directory. The focus is the rule the component's usefulness rests on
-- an answer is only as good as its citation, and citations are checked
against the file, not trusted -- plus the caps and the redaction that keep
the retrieval bounded and secrets out of the context window.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import handler

MAIN_TF = '''resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.public_http_cidrs
  }
}
'''

VARS_TF = '''variable "public_http_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}
'''

TFVARS = '''db_password = "Sup3rS3cret!"
admin_cidrs = ["10.0.0.0/16"]
api_token   = var.token_from_ssm
'''

ISSUER_YAML = '''apiVersion: cert-manager.io/v1
kind: ClusterIssuer
spec:
  acme:
    solvers:
      - http01:
          ingress:
            class: nginx
'''


@pytest.fixture
def snapshot(tmp_path):
    files = {
        "main.tf": MAIN_TF,
        "variables.tf": VARS_TF,
        "terraform.tfvars": TFVARS,
        "k8s/issuer.yaml": ISSUER_YAML,
    }
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return handler.Snapshot(str(tmp_path), list(files))


# ---------- the tools ----------

def test_search_returns_file_line_and_text(snapshot):
    out = snapshot.search(r"http01")

    assert out == "k8s/issuer.yaml:6:       - http01:"


def test_search_is_case_insensitive_and_reports_no_matches(snapshot):
    assert "variables.tf:1:" in snapshot.search("PUBLIC_HTTP_CIDRS")
    assert snapshot.search("nothing-like-this") == "no matches"


def test_search_rejects_a_bad_regex_without_raising(snapshot):
    assert snapshot.search("(").startswith("invalid regular expression")


def test_search_truncates_and_says_so(snapshot, monkeypatch):
    monkeypatch.setattr(handler, "MAX_MATCHES_PER_SEARCH", 2)

    out = snapshot.search(".")

    assert out.count("\n") == 2  # two matches plus the notice
    assert "more than 2 matches" in out


def test_read_file_numbers_lines_and_pages(snapshot, monkeypatch):
    monkeypatch.setattr(handler, "MAX_READ_LINES", 3)

    first = snapshot.read_file("main.tf", 1)
    assert first.startswith('1: resource "aws_security_group" "web" {\n2:   name = "web"\n3: ')
    assert "call again with start_line=4" in first

    assert snapshot.read_file("main.tf", 99) == "main.tf has 10 lines"


def test_read_file_names_the_snapshot_when_the_path_is_wrong(snapshot):
    out = snapshot.read_file("modules/vpc/main.tf", 1)

    assert out.startswith("no such file in the snapshot")
    assert "variables.tf" in out


def test_the_byte_budget_stops_returning_content(snapshot, monkeypatch):
    """A truncated search that answers confidently is the fabrication risk
    in another form, so once the budget is gone the tool says so instead
    of returning a partial view."""
    monkeypatch.setattr(handler, "MAX_TOTAL_BYTES", 50)

    snapshot.read_file("main.tf", 1)  # spends the budget
    out = snapshot.search("ingress")

    assert out.startswith("retrieval budget exhausted")


# ---------- redaction ----------

def test_secret_literals_are_redacted_but_references_are_not(snapshot):
    out = snapshot.read_file("terraform.tfvars", 1)

    assert 'db_password = "<redacted>"' in out
    assert "Sup3rS3cret" not in out
    # The agent may need to follow a reference; it is not a secret.
    assert "api_token   = var.token_from_ssm" in out
    # Not a secret-looking key at all.
    assert 'admin_cidrs = ["10.0.0.0/16"]' in out


@pytest.mark.parametrize("line", [
    'password = "hunter2"',
    'aws_secret_access_key: wJalrXUtnFEMI/K7MDENG',
    '  "api_key" = "abc"',
    "PRIVATE_KEY=-----BEGIN",
])
def test_redaction_covers_the_common_key_spellings(line):
    assert handler.REDACTED in handler._redact(line)


def test_search_results_are_redacted_too(snapshot):
    out = snapshot.search("db_password")

    assert "Sup3rS3cret" not in out
    assert handler.REDACTED in out


# ---------- citation verification ----------

def _answer(answer, citations, question="Q?", explanation="because"):
    return {"question": question, "answer": answer, "explanation": explanation, "citations": citations}


def test_a_verbatim_excerpt_on_the_cited_lines_verifies(snapshot):
    cited = _answer("yes", [{"file": "k8s/issuer.yaml", "line_range": [6, 6], "excerpt": "- http01:"}])

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 0
    assert out[0]["answer"] == "yes"
    assert out[0]["citations"] == [{"file": "k8s/issuer.yaml", "line_range": [6, 6], "excerpt": "- http01:"}]


def test_whitespace_differences_do_not_fail_a_citation(snapshot):
    cited = _answer("yes", [{"file": "main.tf", "line_range": [5, 8],
                              "excerpt": "from_port = 80 to_port = 80"}])

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 0 and out[0]["answer"] == "yes"


def test_a_citation_one_line_off_still_verifies(snapshot):
    """Models are routinely one line off on a block boundary; the point of
    the check is that the words are there, not that the range is exact."""
    cited = _answer("no", [{"file": "variables.tf", "line_range": [4, 4],
                             "excerpt": 'default = ["0.0.0.0/0"]'}])  # actually line 3

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 0 and out[0]["answer"] == "no"


def test_a_fabricated_excerpt_is_rejected_and_the_answer_becomes_unknown(snapshot):
    """The failure that would make this component worse than nothing."""
    cited = _answer("no", [{"file": "main.tf", "line_range": [1, 10],
                             "excerpt": 'cidr_blocks = ["10.0.0.0/8"]'}])

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 1
    assert out[0]["answer"] == "unknown"
    assert out[0]["citations"] == []
    assert "could not be verified" in out[0]["explanation"]


def test_a_citation_to_a_file_not_in_the_snapshot_is_rejected(snapshot):
    cited = _answer("yes", [{"file": "modules/cdn/main.tf", "line_range": [1, 2], "excerpt": "origin"}])

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 1 and out[0]["answer"] == "unknown"


def test_a_citation_of_redacted_text_cannot_verify(snapshot):
    """The model saw <redacted>; the file does not contain it. The citation
    fails, which is the intended outcome -- an answer cannot rest on a
    secret's value."""
    cited = _answer("yes", [{"file": "terraform.tfvars", "line_range": [1, 1],
                              "excerpt": 'db_password = "<redacted>"'}])

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 1 and out[0]["answer"] == "unknown"


def test_unknown_needs_no_citation_and_keeps_a_bad_one_out(snapshot):
    cited = _answer("unknown", [{"file": "main.tf", "line_range": [1, 1], "excerpt": "nope"}])

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 1
    assert out[0]["answer"] == "unknown"
    assert "could not be verified" not in out[0]["explanation"]


def test_only_the_bad_citation_is_dropped_from_a_mixed_set(snapshot):
    cited = _answer("yes", [
        {"file": "k8s/issuer.yaml", "line_range": [2, 2], "excerpt": "kind: ClusterIssuer"},
        {"file": "k8s/issuer.yaml", "line_range": [2, 2], "excerpt": "kind: Issuer"},
    ])

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 1
    assert out[0]["answer"] == "yes"
    assert [c["excerpt"] for c in out[0]["citations"]] == ["kind: ClusterIssuer"]


# ---------- the loop, end to end ----------

def _tool_use(name, input_, id_="tu_1"):
    return SimpleNamespace(type="tool_use", name=name, input=input_, id=id_)


def _response(stop_reason, content):
    return SimpleNamespace(stop_reason=stop_reason, content=content)


def _final(answers):
    return _response("end_turn", [SimpleNamespace(type="text", text=json.dumps({"answers": answers}))])


QUESTION = "Does certificate issuance in this repository rely on ACME HTTP-01?"


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "_download_snapshot")
@patch.object(handler, "shutil")
def test_handler_searches_reads_and_returns_a_verified_answer(
    mock_shutil, mock_download, mock_get_client, snapshot, capsys
):
    """One search, one read, then a cited answer. The tool results the
    model saw are what the snapshot returned, and the final answer went
    through verification."""
    mock_download.return_value = snapshot.files
    with patch.object(handler, "Snapshot", return_value=snapshot):
        create = mock_get_client.return_value.messages.create
        create.side_effect = [
            _response("tool_use", [_tool_use("search", {"pattern": "http01"})]),
            _response("tool_use", [_tool_use("read_file", {"path": "k8s/issuer.yaml", "start_line": 1}, "tu_2")]),
            _final([{"question": QUESTION, "answer": "yes",
                     "explanation": "The ClusterIssuer's ACME solver is http01.",
                     "citations": [{"file": "k8s/issuer.yaml", "line_range": [5, 6], "excerpt": "solvers: - http01:"}]}]),
        ]

        result = handler.handler({"pr_id": "p", "s3_prefix": "scans/p/", "questions": [QUESTION]}, None)

    [answer] = result["answers"]
    assert answer["answer"] == "yes"
    assert answer["citations"][0]["file"] == "k8s/issuer.yaml"

    # The second request carried the search result back as a tool_result.
    # (The handler appends to one list, so the mock's captured reference is
    # the final transcript: prompt, assistant, result, assistant, result.)
    transcript = create.call_args_list[1].kwargs["messages"]
    tool_result = transcript[2]["content"][0]
    assert tool_result["type"] == "tool_result" and tool_result["tool_use_id"] == "tu_1"
    assert "k8s/issuer.yaml:6:" in tool_result["content"]

    # Every request offered the tools and demanded the answer schema.
    for call in create.call_args_list:
        assert [t["name"] for t in call.kwargs["tools"]] == ["search", "read_file"]
        assert call.kwargs["output_config"]["format"]["schema"] is handler.ANSWER_SCHEMA

    # And the metrics line went out.
    emf = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]
    assert emf[-1]["ContextQuestions"] == 1 and emf[-1]["ContextAnswered"] == 1
    assert emf[-1]["ContextCitationsRejected"] == 0


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "_download_snapshot")
@patch.object(handler, "shutil")
def test_the_tool_call_budget_is_enforced_and_announced(
    mock_shutil, mock_download, mock_get_client, snapshot, monkeypatch
):
    monkeypatch.setattr(handler, "MAX_TOOL_CALLS", 1)
    mock_download.return_value = snapshot.files
    with patch.object(handler, "Snapshot", return_value=snapshot):
        create = mock_get_client.return_value.messages.create
        create.side_effect = [
            _response("tool_use", [_tool_use("search", {"pattern": "a"})]),
            _response("tool_use", [_tool_use("search", {"pattern": "b"}, "tu_2")]),
            _final([{"question": QUESTION, "answer": "unknown", "explanation": "ran out", "citations": []}]),
        ]

        handler.handler({"pr_id": "p", "s3_prefix": "scans/p/", "questions": [QUESTION]}, None)

    over_budget = create.call_args_list[2].kwargs["messages"][-1]["content"][0]["content"]
    assert over_budget.startswith("tool-call budget of 1 exhausted")


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "_download_snapshot")
@patch.object(handler, "shutil")
def test_answers_come_back_aligned_to_the_questions_asked(
    mock_shutil, mock_download, mock_get_client, snapshot
):
    """remediation-agent pairs by position. A question the model skipped is
    unknown, and its reordering is undone."""
    mock_download.return_value = snapshot.files
    q1, q2 = "First?", "Second?"
    with patch.object(handler, "Snapshot", return_value=snapshot):
        mock_get_client.return_value.messages.create.return_value = _final([
            {"question": q2, "answer": "unknown", "explanation": "n/a", "citations": []},
        ])

        result = handler.handler({"pr_id": "p", "s3_prefix": "scans/p/", "questions": [q1, q2]}, None)

    assert [a["question"] for a in result["answers"]] == [q1, q2]
    assert result["answers"][0]["explanation"] == "The agent returned no answer for this question."


def test_no_questions_means_no_work():
    assert handler.handler({"pr_id": "p", "s3_prefix": "scans/p/", "questions": []}, None) == {"pr_id": "p", "answers": []}


def test_a_citation_without_a_line_pair_is_rejected(snapshot):
    """The schema cannot pin the pair's length (the API rejects minItems
    above 1), so the verifier does."""
    cited = _answer("yes", [{"file": "main.tf", "line_range": [1], "excerpt": "resource"}])

    out, rejected = handler._verify_citations([cited], snapshot)

    assert rejected == 1 and out[0]["answer"] == "unknown"


def test_a_paraphrased_question_is_aligned_by_position():
    """The model quotes questions verbatim when asked, mostly. When it
    returns one answer per question, a reworded question is that question,
    and the record keeps the wording the draft actually asked."""
    q1, q2 = "Is var.admin_cidrs populated anywhere?", "Does anything serve the bucket publicly?"
    answers = [
        {"question": "Is `admin_cidrs` set in any tfvars?", "answer": "yes", "explanation": "e1", "citations": []},
        {"question": q2, "answer": "no", "explanation": "e2", "citations": []},
    ]

    out = handler._align([q1, q2], answers)

    assert [a["question"] for a in out] == [q1, q2]
    assert [a["answer"] for a in out] == ["yes", "no"]


def test_a_count_mismatch_falls_back_to_exact_text():
    q1, q2 = "First?", "Second?"
    answers = [{"question": q2, "answer": "no", "explanation": "e", "citations": []}]

    out = handler._align([q1, q2], answers)

    assert out[0]["answer"] == "unknown" and "no answer" in out[0]["explanation"]
    assert out[1]["answer"] == "no"
