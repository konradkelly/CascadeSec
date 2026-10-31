"""Stores for the conformance suite: memory always, and DynamoDB Local when
it answers at CASCADESEC_DYNAMODB_ENDPOINT (default http://localhost:8000).

  docker run --rm -p 8000:8000 amazon/dynamodb-local:2.6.1

CI sets CASCADESEC_REQUIRE_DYNAMODB=1, which turns "not running" from a
skip into a failure, so the suite cannot pass there without having held
the AWS adapter to it (portable-runtime-spec §4)."""

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cascadesec_core.memory import MemoryRecordStore  # noqa: E402

ENDPOINT = os.environ.get("CASCADESEC_DYNAMODB_ENDPOINT", "http://localhost:8000")
REQUIRED = os.environ.get("CASCADESEC_REQUIRE_DYNAMODB") == "1"


def _dynamodb():
    import boto3  # noqa: PLC0415
    from botocore.config import Config  # noqa: PLC0415

    # DynamoDB Local takes any credentials; these name nothing real.
    return boto3.resource("dynamodb", endpoint_url=ENDPOINT, region_name="us-west-2",
                          aws_access_key_id="local", aws_secret_access_key="local",
                          config=Config(retries={"max_attempts": 2}, connect_timeout=2, read_timeout=30))


def _dynamodb_running():
    try:
        _dynamodb().meta.client.list_tables(Limit=1)
        return True
    except Exception:
        return False


@pytest.fixture(params=["memory", "dynamodb"])
def make_store(request):
    """A function returning a store over one fresh, empty table. Each call
    is a separate client, as separate processes would be; for memory, the
    same store, since its table is the object."""
    if request.param == "memory":
        store = MemoryRecordStore()
        yield lambda: store
        return

    if not _dynamodb_running():
        if REQUIRED:
            pytest.fail(f"DynamoDB Local is not answering at {ENDPOINT}, and CASCADESEC_REQUIRE_DYNAMODB=1")
        pytest.skip(f"DynamoDB Local is not running at {ENDPOINT}")
    from cascadesec_aws.records import DynamoDBRecordStore  # noqa: PLC0415

    name = f"conformance-{uuid.uuid4().hex[:12]}"
    # The findings table's key schema (terraform/dynamodb.tf): pk and sk, strings.
    table = _dynamodb().create_table(
        TableName=name, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}])
    table.wait_until_exists()
    yield lambda: DynamoDBRecordStore(_dynamodb().Table(name))
    table.delete()
