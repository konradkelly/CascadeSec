"""A cdk-synth run's output, read on the trusted side (docs/sandbox-spec.md
§6, §9 step 2).

The execute task uploads a cloud assembly: manifest.json, each stack's
template, and each stack's metadata. All of it was written by a container
that has just run the pull request's code, so all of it is hostile:

  - the archive is streamed, capped, and never extracted; only regular files
    whose names match what the harness keeps are read at all;
  - every template is parsed and written out again by this module, so what
    the scanner reads is JSON this code produced, whatever the bytes were;
  - every name that becomes part of a key -- an artifact id, a source path
    from a stack trace -- is checked against a strict shape, and refused
    rather than cleaned when it fails.

What it produces, per stack, is the template to scan and its *source map*:
which lines of the rewritten template hold each resource, and which line of
the project's source made it. The map is how a finding on
`NetSsh9740AB70` becomes a finding on `lib/network.ts:8` (multi-iac-spec
§7.2 a). Spans come from this module's own serialisation, not the scanners'
resource names, because the three scanners do not agree on those: Trivy
names some CloudFormation resources by a line range, KICS some by a tag
(measured 2026-10-10). All three agree on lines.

The app can lie in its metadata as easily as in its template (spec §2), so
a source location is a claim, not a fact. It is only ever used to place an
annotation, and github-gateway places one only on a line the pull request
adds -- so a location naming a file outside the diff is simply not shown.
"""

import json
import re
import tarfile

# The archive and what is in it. A template is at most 1MB to CloudFormation
# itself; metadata grows with the construct tree, and CDK_DEBUG's stacks
# make it the largest file here by far.
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_UNPACKED_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 40 * 1024 * 1024
MAX_MEMBERS = 500
MAX_STACKS = 50
MAX_RESOURCES = 2000

# Must match the harness's KEEP_RE (sandbox/image/cdk.mjs). Anything else
# in the archive is skipped unread.
KEEP_RE = re.compile(r"^(?:assembly-[^/]+/)?(?:manifest\.json|[^/]+\.template\.json|[^/]+\.metadata\.json)$")

# The names that become part of an S3 key. CDK's artifact ids are a
# construct path with the slashes dropped; a nested assembly's directory is
# `assembly-` and the stage's id.
ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
ASSEMBLY_DIR_RE = re.compile(r"^assembly-[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
LOGICAL_ID_RE = re.compile(r"^[A-Za-z0-9]{1,255}$")

# Where the harness unpacks the project (cdk.mjs's SRC). A frame under it is
# the project's; anything else is Node, a library, or not a path at all.
SOURCE_ROOT = "/work/src/"
# "new Network (/work/src/infra/lib/network.ts:8:16)", or a bare
# "/work/src/bin/app.ts:4:1" for a frame without a function name.
FRAME_RE = re.compile(r"(?:^|\()" + re.escape(SOURCE_ROOT) + r"([^()\s]+):(\d+):\d+\)?$")


class Hostile(ValueError):
    """The output is not a cloud assembly this module will read."""


# --- the archive ---------------------------------------------------------------

def read_archive(fileobj):
    """{name: bytes} for the members worth reading, streamed under caps."""
    files, total, members = {}, 0, 0
    try:
        with tarfile.open(fileobj=fileobj, mode="r|gz") as tar:
            for member in tar:
                members += 1
                if members > MAX_MEMBERS:
                    raise Hostile(f"more than {MAX_MEMBERS} members")
                if not member.isreg() or not KEEP_RE.match(member.name):
                    continue
                if member.size > MAX_FILE_BYTES:
                    raise Hostile(f"{member.name} is over {MAX_FILE_BYTES // (1024 * 1024)}MB")
                total += member.size
                if total > MAX_UNPACKED_BYTES:
                    raise Hostile(f"over {MAX_UNPACKED_BYTES // (1024 * 1024)}MB unpacked")
                if member.name in files:
                    raise Hostile(f"{member.name} appears twice")
                files[member.name] = tar.extractfile(member).read(MAX_FILE_BYTES + 1)
    except (tarfile.TarError, EOFError, OSError) as e:
        raise Hostile(f"not a readable archive: {type(e).__name__}") from None
    return files


def _json(files, name):
    try:
        return json.loads(files[name].decode("utf-8"))
    except KeyError:
        raise Hostile(f"{name} is missing") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise Hostile(f"{name} is not UTF-8 JSON") from None


# --- the assembly ----------------------------------------------------------------

def stacks(files):
    """[(artifact path, display name, template, metadata)] for every stack,
    following one level of nested assembly (a Stage)."""
    found = []
    _collect_stacks(files, "", found)
    return found


def _collect_stacks(files, directory, found):
    manifest = _json(files, f"{directory}manifest.json")
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if not isinstance(artifacts, dict):
        raise Hostile(f"{directory}manifest.json has no artifacts")
    for artifact_id, artifact in sorted(artifacts.items()):
        if not isinstance(artifact, dict):
            continue
        kind = artifact.get("type")
        props = artifact.get("properties") if isinstance(artifact.get("properties"), dict) else {}
        if kind == "cdk:cloud-assembly" and not directory:
            nested = props.get("directoryName")
            if not (isinstance(nested, str) and ASSEMBLY_DIR_RE.match(nested)):
                raise Hostile(f"nested assembly {nested!r} has an unexpected name")
            _collect_stacks(files, f"{nested}/", found)
            continue
        if kind != "aws:cloudformation:stack":
            continue
        if not ARTIFACT_ID_RE.match(artifact_id):
            raise Hostile(f"stack artifact id {artifact_id[:80]!r} has an unexpected shape")
        if len(found) >= MAX_STACKS:
            raise Hostile(f"more than {MAX_STACKS} stacks")
        template_file = props.get("templateFile")
        if not isinstance(template_file, str) or f"{directory}{template_file}" not in files:
            raise Hostile(f"stack {artifact_id} names no template the archive holds")
        template = _json(files, f"{directory}{template_file}")
        if not (isinstance(template, dict) and isinstance(template.get("Resources", {}), dict)):
            raise Hostile(f"stack {artifact_id}'s template is not a template")
        if len(template.get("Resources", {})) > MAX_RESOURCES:
            raise Hostile(f"stack {artifact_id} has more than {MAX_RESOURCES} resources")
        found.append((f"{directory}{artifact_id}",
                      str(artifact.get("displayName") or artifact_id)[:255],
                      template, _metadata(files, directory, artifact)))


def _metadata(files, directory, artifact):
    """{construct path: [entries]}. In `<Stack>.metadata.json` since
    CLI 2.1144's assembly (probe a); inline in the manifest before that."""
    name = artifact.get("additionalMetadataFile")
    if isinstance(name, str):
        metadata = _json(files, f"{directory}{name}") if f"{directory}{name}" in files else {}
    else:
        metadata = artifact.get("metadata") or {}
    return metadata if isinstance(metadata, dict) else {}


# --- the source map ----------------------------------------------------------------

def _repo_path(path):
    """The repository-relative path a frame names, or None: the same refusal
    github-gateway's repo_path makes, plus nothing under node_modules."""
    if path.startswith("/") or "\\" in path or len(path) > 1024:
        return None
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts) or "node_modules" in parts:
        return None
    return path


def _user_frame(trace):
    if not isinstance(trace, list):
        return None
    for frame in trace[:200]:
        match = FRAME_RE.search(frame) if isinstance(frame, str) else None
        if match:
            path, line = _repo_path(match.group(1)), int(match.group(2))
            if path and 0 < line < 10_000_000:
                return {"file": path, "line": line}
    return None


def source_map(metadata):
    """{logical id: {path, file, line, assignments}} and the stack's own
    creation site, from the metadata's per-construct entries.

    A construct the user wrote has its creation stack. One a library made
    for itself -- a Vpc's subnets -- is attributed to its nearest ancestor
    that has a user frame, which is the line that made the library
    construct. The harness's deeper stack limit makes that walk rare."""
    by_path, logical_ids = {}, {}
    for path, entries in metadata.items():
        if not (isinstance(path, str) and path.startswith("/") and isinstance(entries, list)):
            continue
        site, assignments = None, []
        for entry in entries[:50]:
            if not isinstance(entry, dict):
                continue
            kind, data = entry.get("type"), entry.get("data")
            if kind == "aws:cdk:logicalId" and isinstance(data, str) and LOGICAL_ID_RE.match(data):
                logical_ids[data] = path
            elif kind == "aws:cdk:creationStack":
                site = site or _user_frame(data)
            elif kind == "aws:cdk:propertyAssignment" and isinstance(data, dict):
                frame = _user_frame(data.get("stackTrace"))
                prop = data.get("propertyName")
                if frame and isinstance(prop, str):
                    assignments.append({"property": prop[:255], **frame})
        by_path[path] = {"site": site, "assignments": assignments[:20]}

    def nearest_site(path):
        while path:
            site = (by_path.get(path) or {}).get("site")
            if site:
                return site
            path = path.rsplit("/", 1)[0]
        return None

    resources = {}
    for logical_id, path in logical_ids.items():
        site = nearest_site(path) or {}
        resources[logical_id] = {
            "path": path[:1024],
            "file": site.get("file"),
            "line": site.get("line"),
            "assignments": by_path[path]["assignments"],
        }
    # Every path in a stack's metadata starts with the stack's own, so the
    # shortest is the stack: its site is the line that created it, which is
    # where a finding outside any resource is placed.
    stack_site = nearest_site(min(by_path, key=len)) if by_path else None
    return resources, stack_site


# --- the rewritten template ---------------------------------------------------------

def render(template):
    """The template as this module writes it, and each resource's lines in it.

    indent=1 is how CDK writes templates, so a reader comparing the two sees
    the same shape. The spans are read back off this text rather than
    reconstructed, and that is safe only because the text is ours: under
    "Resources" at one space, each resource opens on a line at two spaces
    with its (pattern-checked) logical id and closes at two spaces."""
    text = json.dumps(template, indent=1, ensure_ascii=False) + "\n"
    spans, section, current = {}, None, None
    for number, line in enumerate(text.split("\n"), start=1):
        top = re.match(r'^ "([^"]+)": ', line)
        if top:
            section = top.group(1)
            continue
        if section != "Resources":
            continue
        opened = re.match(r'^  "([A-Za-z0-9]+)": (\{\}|\{)(,?)$', line)
        if opened and current is None:
            if opened.group(2) == "{}":
                spans[opened.group(1)] = (number, number)
            else:
                current = (opened.group(1), number)
        elif current and re.match(r"^  \},?$", line):
            spans[current[0]] = (current[1], number)
            current = None
    return text, spans


# --- all of it ------------------------------------------------------------------

def build(files, app_dir):
    """What collect writes for one app: {relative key: bytes}, and a summary
    small enough for the execution's state."""
    outputs, summary = {}, []
    base = "cdk.out/" if app_dir == "." else f"{app_dir}/cdk.out/"
    for artifact_path, name, template, metadata in stacks(files):
        text, spans = render(template)
        resources, stack_site = source_map(metadata)
        types = {lid: r.get("Type") for lid, r in template.get("Resources", {}).items()
                 if isinstance(r, dict)}
        mapped = {}
        for logical_id, (start, end) in spans.items():
            entry = resources.get(logical_id) or {"path": None, "file": None, "line": None, "assignments": []}
            mapped[logical_id] = {"lines": [start, end],
                                  "type": types.get(logical_id) if isinstance(types.get(logical_id), str) else None,
                                  **entry}
        template_key = f"{base}{artifact_path}.template.json"
        outputs[template_key] = text.encode("utf-8")
        outputs[sources_key(template_key)] = json.dumps({
            "app": app_dir, "stack": name, "artifact": artifact_path,
            "site": stack_site, "resources": mapped,
        }, sort_keys=True).encode("utf-8")
        summary.append({
            "stack": name,
            "template": template_key,
            "resources": len(spans),
            # Resources with no line in the project: worth seeing, because
            # a finding on one is annotated at the stack's site instead.
            "unlocated": sum(1 for m in mapped.values() if not m["file"]),
        })
    return outputs, summary


def sources_key(template_key):
    """Where a template's source map sits: beside it, under a suffix no
    uploader or scanner admits, so it is never scanned as a file. The
    scanner reads it by this name (iac-scanner's _cdk_origins)."""
    return template_key[: -len(".json")] + ".sources"


def missing_context(files):
    """The lookups the app asked for and the cached context did not have.
    Without credentials they cannot be made, so the run reports them
    (spec §1: a lookup without a committed cdk.context.json)."""
    manifest = _json(files, "manifest.json")
    missing = manifest.get("missing") if isinstance(manifest, dict) else None
    if not isinstance(missing, list):
        return []
    return sorted({str(m.get("provider"))[:80] for m in missing[:100] if isinstance(m, dict)})
