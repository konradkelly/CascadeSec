import copy

import pytest

import pulumi_plan


def resource(token, name, inputs, references=None):
    return {"urn": f"urn:pulumi:sandbox::test::{token}::{name}", "type": token, "name": name,
            "custom": True, "inputs": inputs, "references": references or {}, "dependencies": {},
            "source": {"file": "index.ts", "line": 5}}


def document(resources):
    return {"schema_version": 2, "provider_versions": {"aws": "7.48.0"}, "resources": resources}


def test_nested_blocks_pluralization_maps_and_references():
    bucket = resource("aws:s3/bucket:Bucket", "logs", {"tags": {"CamelCaseUserKey": "preserved"}})
    encryption = resource("aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration", "enc",
        {"bucket": "mock-value", "rules": [{"applyServerSideEncryptionByDefault": {"sseAlgorithm": "aws:kms"}}]},
        {"/bucket": [bucket["urn"]]})
    instance = resource("aws:ec2/instance:Instance", "server", {"metadataOptions": {"httpTokens": "required"}})
    plan = pulumi_plan.build(document([bucket, encryption, instance]))
    planned = {r["address"]: r["values"] for r in plan["planned_values"]["root_module"]["resources"]}
    assert planned["aws_instance.server"]["metadata_options"] == [{"http_tokens": "required"}]
    assert planned["aws_s3_bucket.logs"]["tags"] == {"CamelCaseUserKey": "preserved"}
    assert planned["aws_s3_bucket_server_side_encryption_configuration.enc"]["rule"] == [
        {"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]
    expressions = {r["address"]: r["expressions"] for r in plan["configuration"]["root_module"]["resources"]}
    assert expressions["aws_instance.server"]["metadata_options"] == [{"http_tokens": {"constant_value": "required"}}]
    assert expressions["aws_s3_bucket_server_side_encryption_configuration.enc"]["bucket"]["references"] == ["aws_s3_bucket.logs.id", "aws_s3_bucket.logs"]


def test_equal_constants_do_not_become_references():
    plan = pulumi_plan.build(document([resource("aws:s3/bucket:Bucket", "a", {"bucket": "same"}),
        resource("aws:s3/bucketLogging:BucketLogging", "b", {"bucket": "same", "targetBucket": "same"})]))
    assert "references" not in plan["configuration"]["root_module"]["resources"][1]["expressions"]["bucket"]


@pytest.mark.parametrize("change", ["provider", "type", "legacy", "secret", "missing", "duplicate"])
def test_unsupported_captures_never_produce_partial_plans(change):
    r = resource("aws:s3/bucket:Bucket", "a", {})
    data = document([r])
    if change == "provider": data["provider_versions"]["aws"] = "8.0.0"
    if change == "type": r["type"] = "azure-native:storage:StorageAccount"
    if change == "legacy": data["schema_version"] = 1
    if change == "secret": r["inputs"] = {"bucket": {"secret": True}}
    if change == "missing": r["inputs"] = {"bucket": "mock"}; r["references"] = {"/bucket": ["unknown"]}
    if change == "duplicate": data["resources"].append(copy.deepcopy(r))
    with pytest.raises(pulumi_plan.Unsupported): pulumi_plan.build(data)


def test_duplicate_names_under_different_parents_get_distinct_addresses():
    r = resource("aws:s3/bucket:Bucket", "a", {})
    other = copy.deepcopy(r)
    other["urn"] = other["urn"].replace("::aws:", "::component$aws:")
    plan = pulumi_plan.build(document([r, other]))
    assert len({r["address"] for r in plan["resource_changes"]}) == 2


def test_unknown_mock_output_is_kept_as_a_reference():
    key = resource("aws:kms/key:Key", "key", {})
    trail = resource("aws:cloudtrail/trail:Trail", "trail", {"s3BucketName": "logs"}, {"/kmsKeyId": [key["urn"]]})
    plan = pulumi_plan.build(document([key, trail]))
    expressions = plan["configuration"]["root_module"]["resources"][0]["expressions"]
    assert expressions["kms_key_id"]["references"][0] == "aws_kms_key.key.id"
    assert plan["resource_changes"][0]["change"]["after_unknown"]["kms_key_id"] is True


def test_whole_block_dependencies_are_explicitly_unsupported():
    r = resource("aws:ec2/instance:Instance", "a", {"metadataOptions": {"httpTokens": "required"}},
                 {"/metadataOptions": ["urn:pulumi:sandbox::test::aws:ec2/instance:Instance::a"]})
    with pytest.raises(pulumi_plan.Unsupported, match="whole-block"):
        pulumi_plan.build(document([r]))


def test_inline_policies_pluralization_preserves_iam_policy_blocks():
    r = resource("aws:iam/role:Role", "role", {"inlinePolicies": [{"name": "inline", "policy": "{}"}]})
    plan = pulumi_plan.build(document([r]))
    assert plan["resource_changes"][0]["change"]["after"]["inline_policy"] == [{"name": "inline", "policy": "{}"}]


def test_component_cannot_hide_unexpanded_infrastructure_in_a_partial_plan():
    bucket = resource("aws:s3/bucket:Bucket", "logs", {})
    component = resource("awsx:ecs:FargateService", "service", {})
    component["custom"] = False
    with pytest.raises(pulumi_plan.Unsupported, match="component resources"):
        pulumi_plan.build(document([bucket, component]))
