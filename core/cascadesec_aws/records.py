"""The RecordStore port on DynamoDB: each operation turned back into the
expression it replaced (portable-runtime-spec §3), so the AWS runtime's
writes stay the writes it makes today, and DynamoDB enforces each
condition atomically as it does now.

Numbers cross the boundary here: DynamoDB takes and returns Decimal, and
the port speaks int and float, so a caller never meets a Decimal.
"""

from decimal import Decimal

from botocore.exceptions import ClientError

from cascadesec_core.records import (Absent, AbsentOr, Conflict, Exists, Missing, PathError, RecordStore,
                                     StatusIn, StatusIs)


class DynamoDBRecordStore(RecordStore):
    """Over a boto3 Table resource, which the caller builds, as the
    handlers build theirs today (a client constructed at import)."""

    def __init__(self, table):
        self.table = table

    def get(self, pk, sk):
        item = self.table.get_item(Key={"pk": pk, "sk": sk}).get("Item")
        return _from_dynamo(item) if item is not None else None

    def query(self, pk, sk_prefix="", attributes=None):
        expr = _Expression()
        key = f"{expr.name('pk')} = {expr.value('pk', pk)}"
        if sk_prefix:
            key += f" AND begins_with({expr.name('sk')}, {expr.value('sk', sk_prefix)})"
        kwargs = {"KeyConditionExpression": key}
        if attributes is not None:
            kwargs["ProjectionExpression"] = ", ".join(expr.path(a) for a in ["pk", "sk", *attributes])
        kwargs.update(expr.arguments())
        # Every page: a query stops at 1 MB, and the caller is owed every item
        # (G9). Ascending by sk is DynamoDB's own order.
        items = []
        while True:
            response = self.table.query(**kwargs)
            items += response.get("Items", [])
            if "LastEvaluatedKey" not in response:
                return [_from_dynamo(i) for i in items]
            kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    def put(self, item, unless_exists=False):
        kwargs = {"Item": _to_dynamo(item)}
        if unless_exists:
            kwargs["ConditionExpression"] = "attribute_not_exists(sk)"
        try:
            self.table.put_item(**kwargs)
        except ClientError as e:
            raise _translated(e, item["pk"], item["sk"]) from None

    def update(self, pk, sk, set=None, set_if_absent=None, remove=(), condition=None):
        expr = _Expression()
        sets = [f"{expr.path(path)} = {expr.value('s', v)}" for path, v in (set or {}).items()]
        sets += [f"{expr.path(n)} = if_not_exists({expr.path(n)}, {expr.value('i', v)})"
                 for n, v in (set_if_absent or {}).items()]
        clauses = []
        if sets:
            clauses.append("SET " + ", ".join(sets))
        if remove:
            clauses.append("REMOVE " + ", ".join(expr.path(n) for n in remove))
        kwargs = {"Key": {"pk": pk, "sk": sk}, "ReturnValues": "ALL_NEW"}
        if clauses:
            kwargs["UpdateExpression"] = " ".join(clauses)
        if condition is not None:
            kwargs["ConditionExpression"] = _condition(condition, expr)
        kwargs.update(expr.arguments())
        try:
            return _from_dynamo(self.table.update_item(**kwargs)["Attributes"])
        except ClientError as e:
            raise _translated(e, pk, sk) from None


def _condition(condition, expr):
    if isinstance(condition, StatusIs):
        return f"{expr.path('status')} = {expr.value('c', condition.value)}"
    if isinstance(condition, StatusIn):
        return f"{expr.path('status')} IN ({', '.join(expr.value('c', v) for v in condition.values)})"
    if isinstance(condition, Exists):
        return f"attribute_exists({expr.path(condition.attribute)})"
    if isinstance(condition, Missing):
        return f"attribute_not_exists({expr.path(condition.attribute)})"
    if isinstance(condition, Absent):
        return f"attribute_not_exists({expr.path('sk')})"
    if isinstance(condition, AbsentOr):
        return f"attribute_not_exists({expr.path('sk')}) OR ({_condition(condition.condition, expr)})"
    raise TypeError(f"not a condition: {condition!r}")


class _Expression:
    """Placeholders for one request: every name goes through one (status,
    source, file and resource are reserved words), and every value too."""

    def __init__(self):
        self.names, self.values = {}, {}

    def name(self, name):
        for placeholder, existing in self.names.items():
            if existing == name:
                return placeholder
        placeholder = f"#n{len(self.names)}"
        self.names[placeholder] = name
        return placeholder

    def path(self, path):
        return ".".join(self.name(part) for part in path.split("."))

    def value(self, prefix, value):
        placeholder = f":{prefix}{len(self.values)}"
        self.values[placeholder] = _to_dynamo(value)
        return placeholder

    def arguments(self):
        out = {}
        if self.names:
            out["ExpressionAttributeNames"] = self.names
        if self.values:
            out["ExpressionAttributeValues"] = self.values
        return out


def _translated(error, pk, sk):
    code = error.response.get("Error", {}).get("Code")
    message = error.response.get("Error", {}).get("Message", "")
    if code == "ConditionalCheckFailedException":
        return Conflict(f"{pk} {sk}: condition does not hold")
    if code == "ValidationException" and "document path" in message:
        return PathError(f"{pk} {sk}: {message}")
    return error


def _to_dynamo(value):
    if isinstance(value, bool) or value is None or isinstance(value, (str, int, Decimal)):
        return value
    if isinstance(value, float):
        # str, not the float itself: Decimal(0.1) is 0.1000000000000000055...
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_dynamo(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_dynamo(v) for v in value]
    raise TypeError(f"a record cannot hold {type(value).__name__}")


def _from_dynamo(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _from_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_dynamo(v) for v in value]
    return value
