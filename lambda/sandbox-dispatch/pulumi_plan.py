"""Trusted, versioned AWS bridge: mocked Pulumi inputs -> Terraform plan JSON.

Never infer links by matching values. References are SDK dependency URNs.
Unsupported resources or provider versions reject the whole conversion.
"""
import hashlib
import json
from pathlib import Path
import re


class Unsupported(ValueError):
    pass


BRIDGE = json.loads(Path(__file__).with_name("aws-bridge.json").read_text())
TOKENS = {}
for terraform_type, metadata in BRIDGE["resources"].items():
    for token in [metadata["current"], *(p["name"] for p in metadata.get("past", []))]:
        TOKENS[token] = (terraform_type, metadata.get("fields", {}))


def _snake(name):
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def _pointer(base, key):
    return base + "/" + str(key).replace("~", "~0").replace("/", "~1")


def _convert(inputs, fields, refs, addresses, pointer="", used=None):
    used = used if used is not None else set()
    inputs = dict(inputs)
    for at, urns in refs.items():
        suffix = at[len(pointer) + 1:] if at.startswith(pointer + "/") else None
        if urns and suffix and "/" not in suffix:
            inputs.setdefault(suffix.replace("~1", "/").replace("~0", "~"), None)
    values, expressions = {}, {}
    for key, value in sorted(inputs.items()):
        field = _snake(key)
        if field not in fields:
            singulars = [field[:-3] + "y"] if field.endswith("ies") else []
            if field.endswith("s"): singulars.append(field[:-1])
            field = next((candidate for candidate in singulars if candidate in fields), field)
        if field in values:
            raise Unsupported(f"two properties map to {field}")
        metadata = fields.get(field, {})
        at = _pointer(pointer, key)
        if value == {"secret": True}:
            raise Unsupported(f"redacted secret at {at}; its value cannot be evaluated")
        # Objects whose bridge flattens one Terraform block, or arrays of blocks.
        block = metadata.get("maxItemsOne") is True or (
            isinstance(value, list) and any(isinstance(v, dict) for v in value)
            and "maxItemsOne" in metadata)
        if block:
            if refs.get(at):
                raise Unsupported(f"whole-block output dependency at {at} cannot be represented precisely")
            items = [value] if metadata.get("maxItemsOne") is True else value
            if not isinstance(items, list) or any(not isinstance(v, dict) for v in items):
                raise Unsupported(f"invalid block at {at}")
            blocks, block_expressions = [], []
            for index, item in enumerate(items):
                block_pointer = at if metadata.get("maxItemsOne") is True else _pointer(at, index)
                v, e = _convert(item, metadata.get("elem", {}).get("fields", {}), refs, addresses, block_pointer, used)
                blocks.append(v)
                block_expressions.append(e)
            values[field], expressions[field] = blocks, block_expressions
        else:
            # Maps (tags, etc.) retain their user-defined keys.
            values[field] = value
            dependencies = refs.get(at, [])
            expression = {"constant_value": value}
            if dependencies:
                used.add(at)
                unknown = set(dependencies) - addresses.keys()
                if unknown:
                    raise Unsupported(f"references at {at} name unsupported resources")
                targets = sorted({addresses[u] for u in dependencies})
                expression = {"references": [a + ".id" for a in targets] + targets}
                # Mock IDs are not known deployment values. Trivy reconstructs
                # references only where the plan correctly marks a value unknown.
                del values[field]
            expressions[field] = expression
    return values, expressions


def _unknowns(expressions):
    unknown = {}
    for key, value in expressions.items():
        if isinstance(value, list):
            children = [_unknowns(item) for item in value]
            if any(children): unknown[key] = children
        elif "references" in value:
            unknown[key] = True
    return unknown


def build(document):
    if document.get("schema_version") != 2:
        raise Unsupported("resource capture v2 is required for exact dependency references; rerun the sandbox")
    if document.get("provider_versions", {}).get("aws") != BRIDGE["version"]:
        raise Unsupported(f"AWS adapter requires @pulumi/aws {BRIDGE['version']}")
    selected = []
    for resource in document["resources"]:
        if resource["type"].startswith("pulumi:providers:") or resource["type"] == "pulumi:pulumi:Stack":
            continue
        if not resource["custom"]:
            # Remote components are not expanded by the mock engine. The
            # capture cannot distinguish them safely from local components.
            raise Unsupported(f"component resources are not supported: {resource['type']}")
        if resource["type"] not in TOKENS:
            raise Unsupported(f"unsupported resource type: {resource['type']}")
        selected.append(resource)
    addresses, seen = {}, set()
    for resource in sorted(selected, key=lambda r: r["urn"]):
        terraform_type, _ = TOKENS[resource["type"]]
        name = resource["name"]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            name = "r_" + hashlib.sha256(resource["urn"].encode()).hexdigest()[:16]
        address = f"{terraform_type}.{name}"
        if address in seen:
            address += "_" + hashlib.sha256(resource["urn"].encode()).hexdigest()[:16]
        if resource["urn"] in addresses:
            raise Unsupported("duplicate resource URN")
        addresses[resource["urn"]] = address
        seen.add(address)
    planned, configuration, changes, sources = [], [], [], {}
    for resource in sorted(selected, key=lambda r: addresses[r["urn"]]):
        address = addresses[resource["urn"]]
        terraform_type, fields = TOKENS[resource["type"]]
        used = set()
        refs = resource.get("references", {})
        values, expressions = _convert(resource["inputs"], fields, refs, addresses, used=used)
        if {at for at, urns in refs.items() if urns} - used:
            raise Unsupported(f"unrepresentable nested input references on {address}")
        # Registration dependencies also cover promises and whole-object outputs.
        # Never silently drop a dependency whose nested location we cannot represent.
        captured = {u for us in resource.get("references", {}).values() for u in us}
        for key, urns in resource.get("dependencies", {}).items():
            if set(urns) - captured:
                raise Unsupported(f"dependency on {address}.{key} has no exact input reference")
        common = {"address": address, "mode": "managed", "type": terraform_type,
                  "name": address.split(".", 1)[1], "provider_name": "registry.terraform.io/hashicorp/aws"}
        planned.append({**common, "schema_version": 0, "values": values})
        configuration.append({**common, "provider_config_key": "aws", "expressions": expressions})
        changes.append({**common, "change": {"actions": ["create"], "before": None,
                                             "after": values, "after_unknown": _unknowns(expressions)}})
        sources[address] = {"urn": resource["urn"], "type": resource["type"],
                            "name": resource["name"], "source": resource.get("source")}
    return {"format_version": "1.2", "terraform_version": "1.9.8", "variables": {},
            "planned_values": {"root_module": {"resources": planned}}, "resource_changes": changes,
            "configuration": {"provider_config": {"aws": {"name": "aws", "full_name": "registry.terraform.io/hashicorp/aws"}},
                              "root_module": {"resources": configuration}},
            "cascade_pulumi": {"schema_version": 1, "mode": "mock", "provider_version": BRIDGE["version"],
                               "sources": sources}}
