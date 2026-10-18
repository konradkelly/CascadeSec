"""local_main.py: the copy that decides what local mode scans, and the one
JSON document it prints. The tools are not run here -- scan_directory is
replaced -- because which files reach them is the part this module owns;
the image run in docs/cli-spec.md §3.4's measurement covers the rest."""

import io
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import handler
import local_main

REPO_CORPUS = Path(__file__).resolve().parents[2] / "corpus"


@pytest.fixture(autouse=True)
def corpus(monkeypatch):
    """The image's /opt/corpus is the repository's corpus/, copied in."""
    monkeypatch.setattr(local_main, "CORPUS_DIR", str(REPO_CORPUS))


ARM = json.dumps({"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                  "resources": []})


def tree(root, files):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def test_the_copy_holds_what_the_pipeline_would_scan(tmp_path):
    src = tree(tmp_path / "src", {
        "main.tf": 'resource "aws_s3_bucket" "b" {}',
        "k8s/app.yaml": "kind: Pod",
        "azure/storage.json": ARM,
        "package-lock.json": "{}",                 # a .json that is no template: dropped
        "README.md": "# hi",                       # not a candidate at all
        ".terraform/modules/x/main.tf": "",        # SKIP_DIRS
        "node_modules/pkg/main.tf": "",
        "infra/cdk.out/App.template.json": "{}",
    })
    work = tmp_path / "work"
    work.mkdir()

    snapshot, apps = local_main.copy_snapshot(str(src), str(work))

    copied = sorted(Path(p).relative_to(work).as_posix() for p in snapshot.downloaded)
    assert copied == ["azure/storage.json", "k8s/app.yaml", "main.tf"]
    assert snapshot.classifications == {"azure/storage.json": "arm"}
    assert not (work / "package-lock.json").exists()   # _admit removed it, as the Lambda would
    assert apps == []


def test_apps_that_must_run_first_are_listed_not_scanned(tmp_path):
    src = tree(tmp_path / "src", {
        "infra/cdk.json": "{}", "infra/lib/stack.ts": "",
        "pulumi/Pulumi.yaml": "name: p", "chart/Chart.yaml": "name: c",
        "chart/templates/deploy.yaml": "kind: {{ .Values.kind }}",
        "cdk.json": "{}",
    })
    work = tmp_path / "work"
    work.mkdir()

    _, apps = local_main.copy_snapshot(str(src), str(work))

    assert [(a["path"], a["kind"]) for a in apps] == [
        (".", "cdk"), ("chart", "helm"), ("infra", "cdk"), ("pulumi", "pulumi")]
    assert all(a["reason"] for a in apps)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_symlink_is_neither_followed_nor_copied(tmp_path):
    outside = tree(tmp_path / "outside", {"secret.tf": "x"})
    src = tree(tmp_path / "src", {"main.tf": ""})
    os.symlink(outside / "secret.tf", src / "link.tf")
    os.symlink(outside, src / "linkdir")
    work = tmp_path / "work"
    work.mkdir()

    snapshot, _ = local_main.copy_snapshot(str(src), str(work))

    assert [Path(p).name for p in snapshot.downloaded] == ["main.tf"]


def test_main_prints_one_json_document_and_keeps_stdout_clean(tmp_path, capsys):
    src = tree(tmp_path / "src", {"main.tf": 'resource "aws_s3_bucket" "b" {}', "infra/cdk.json": "{}"})
    record = {"pk": "PR#local", "sk": "FINDING#a", "finding_id": "a", "fingerprint": "f", "source": "trivy",
              "rule_id": "AWS-0086", "file": "main.tf", "line_range": [1, 1], "severity": "HIGH",
              "status": "raw", "control_mappings": [], "proposed_fix": None, "created_at": "t"}

    def noisy_scan(*args, **kwargs):
        print("a tool's chatter")                  # must not reach stdout
        return [dict(record)], ["bad.tf"]

    out = io.StringIO()
    with patch.object(handler, "scan_directory", side_effect=noisy_scan):
        assert local_main.main([str(src)], stdout=out) == 0

    result = json.loads(out.getvalue())
    assert result["scanned_files"] == 1 and result["scan_errors"] == ["bad.tf"]
    (finding,) = result["findings"]
    assert finding["fingerprint"] == "f" and finding["rule_id"] == "AWS-0086"
    # A stored review item's fields are not true of a scan that stored nothing.
    assert not {"pk", "sk", "status", "control_mappings", "proposed_fix", "created_at"} & set(finding)
    assert result["unscanned_apps"][0]["kind"] == "cdk"
    assert "a tool's chatter" in capsys.readouterr().err


def test_nothing_admitted_still_answers(tmp_path):
    src = tree(tmp_path / "src", {"README.md": "", "infra/cdk.json": "{}"})
    out = io.StringIO()
    with patch.object(handler, "scan_directory", side_effect=AssertionError("nothing to scan")):
        assert local_main.main([str(src)], stdout=out) == 0
    result = json.loads(out.getvalue())
    assert (result["scanned_files"], result["findings"]) == (0, [])
    assert result["unscanned_apps"] == [{"path": "infra", "kind": "cdk",
                                         "reason": local_main.APP_REASONS["cdk"]}]


def test_a_missing_directory_is_a_usage_error(tmp_path):
    assert local_main.main([str(tmp_path / "nope")], stdout=io.StringIO()) == 2


# ---------- what a remote scan would make of each finding ----------

def scanner_finding(source, rule_id, target_type="terraform"):
    return {"source": source, "rule_id": rule_id, "target_type": target_type, "file": "x"}


def test_a_mapped_rule_lists_its_candidates_with_titles():
    f = local_main.annotate(scanner_finding("trivy", "AWS-0086"), local_main.load_corpus())

    assert {"framework": "CIS-AWS-1.4", "control_id": "2.1.5"}.items() <= f["candidates"][0].items()
    assert f["candidates"][0]["title"]
    assert "raw_reason" not in f and "detection_only" not in f


def test_a_triaged_rule_says_why_it_stays_raw():
    f = local_main.annotate(scanner_finding("checkov", "CKV_AZURE_43", "arm"), local_main.load_corpus())
    assert (f["candidates"], f["raw_reason"]) == ([], "hygiene")


def test_an_unknown_rule_is_unreviewed():
    f = local_main.annotate(scanner_finding("trivy", "AWS-9999"), local_main.load_corpus())
    assert f["raw_reason"] == "unreviewed"


def test_a_scoped_candidate_is_offered_only_to_its_target_type():
    """CKV_SECRET_6's CIS Kubernetes candidate is for Kubernetes findings
    alone: mapping-agent's rule, applied locally."""
    corpus = local_main.load_corpus()
    k8s = local_main.annotate(scanner_finding("checkov", "CKV_SECRET_6", "kubernetes"), corpus)
    tf = local_main.annotate(scanner_finding("checkov", "CKV_SECRET_6", "terraform"), corpus)
    assert "CIS-Kubernetes-2.0" in {c["framework"] for c in k8s["candidates"]}
    assert "CIS-Kubernetes-2.0" not in {c["framework"] for c in tf["candidates"]}


@pytest.mark.parametrize("target_type", ["cdk", "pulumi"])
def test_cdk_and_pulumi_are_detection_only(target_type):
    f = local_main.annotate(scanner_finding("trivy", "AWS-0086", target_type), local_main.load_corpus())
    assert f["detection_only"] is True


def test_an_image_without_its_corpus_fails_before_scanning(tmp_path, monkeypatch):
    monkeypatch.setattr(local_main, "CORPUS_DIR", str(tmp_path))
    with patch.object(handler, "scan_directory", side_effect=AssertionError("must not scan")):
        with pytest.raises(SystemExit) as e:
            local_main.main([str(tmp_path)], stdout=io.StringIO())
    assert "--build-context corpus" in str(e.value)
