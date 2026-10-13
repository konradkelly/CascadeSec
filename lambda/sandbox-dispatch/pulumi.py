"""Validate hostile Pulumi mock output before trusted plan conversion."""
import json
import math
import tarfile

import cdk

MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_RESOURCES = 2000
Hostile = cdk.Hostile


def read_resources(body, app_dir):
    data = None
    try:
        with tarfile.open(fileobj=body, mode="r|gz") as archive:
            for count, member in enumerate(archive, 1):
                if count > 10:
                    raise Hostile("too many archive members")
                if member.name != "resources.json" or not member.isreg():
                    raise Hostile("archive must contain only a regular resources.json")
                if data is not None or member.size > MAX_FILE_BYTES:
                    raise Hostile("resources.json repeated or too large")
                data = json.loads(archive.extractfile(member).read(MAX_FILE_BYTES + 1),
                                  parse_constant=lambda _: _invalid_number(), parse_float=_finite_float)
    except (tarfile.TarError, EOFError, OSError, ValueError, RecursionError) as e:
        raise Hostile(f"invalid Pulumi output: {str(e)[:200]}") from None
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data.get("schema_version") not in (1, 2) or data.get("mode") != "mock"):
        raise Hostile("unsupported Pulumi output schema")
    for field in ("project", "stack"):
        if not isinstance(data.get(field), str) or not 1 <= len(data[field]) <= 255:
            raise Hostile(f"invalid {field}")
    resources = data.get("resources")
    if not isinstance(resources, list) or len(resources) > MAX_RESOURCES:
        raise Hostile("invalid resource list")
    clean = []
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("inputs"), dict):
            raise Hostile("resource must have an inputs object")
        for field in ("type", "name"):
            if not isinstance(resource.get(field), str) or not 1 <= len(resource[field]) <= 1024:
                raise Hostile(f"invalid resource {field}")
        if not isinstance(resource.get("custom"), bool):
            raise Hostile("resource must identify whether it is custom")
        source = resource.get("source")
        if source is not None:
            if not isinstance(source, dict) or not isinstance(source.get("file"), str) or not cdk._repo_path(source["file"]):
                raise Hostile("invalid resource source path")
            line = source.get("line")
            if not isinstance(line, int) or isinstance(line, bool) or not 1 <= line <= 1000000:
                raise Hostile("invalid resource source line")
            source = {"file": source["file"] if app_dir == "." else f"{app_dir}/{source['file']}", "line": line}
        clean.append({"type": resource["type"], "name": resource["name"], "custom": resource["custom"],
                      "inputs": resource["inputs"], "source": source})
        if data["schema_version"] == 2:
            urn = resource.get("urn")
            if not isinstance(urn, str) or not urn.startswith("urn:pulumi:") or len(urn) > 4096:
                raise Hostile("invalid resource URN")
            clean[-1].update(urn=urn, references=_references(resource.get("references", {})),
                             dependencies=_references(resource.get("dependencies", {})))
    versions = data.get("provider_versions", {})
    if not isinstance(versions, dict) or any(not isinstance(v, str) or len(v) > 100 for v in versions.values()):
        raise Hostile("invalid provider versions")
    return {"schema_version": data["schema_version"], "mode": "mock", "project": data["project"],
            "stack": data["stack"], "resources": clean, "provider_versions": versions}


def _references(value):
    if not isinstance(value, dict) or len(value) > 2000:
        raise Hostile("invalid dependency map")
    for key, urns in value.items():
        if (not isinstance(key, str) or len(key) > 2048 or not isinstance(urns, list) or len(urns) > MAX_RESOURCES
                or any(not isinstance(u, str) or not u.startswith("urn:pulumi:") or len(u) > 4096 for u in urns)):
            raise Hostile("invalid dependency reference")
    return value


def _invalid_number():
    raise ValueError("non-finite JSON number")


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        _invalid_number()
    return value
