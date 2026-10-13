"""Bounded Helm output transport. YAML validity is checked by iac-scanner.

Read without extracting. No source line is inferred from Helm's Source
comments: locations in this output belong to the rendered manifest only.
"""
import tarfile

MAX_ARCHIVE_BYTES = 12 * 1024 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024


class Hostile(ValueError):
    pass


def read_manifest(fileobj):
    manifest = None
    try:
        with tarfile.open(fileobj=fileobj, mode="r|gz") as tar:
            for member in tar:
                if manifest is not None or member.name != "manifests.yaml" or not member.isreg():
                    raise Hostile("expected exactly one regular manifests.yaml")
                if member.size > MAX_FILE_BYTES:
                    raise Hostile("Helm manifest exceeds 10MB")
                manifest = tar.extractfile(member).read(MAX_FILE_BYTES + 1)
                if len(manifest) != member.size:
                    raise Hostile("truncated Helm manifest")
        text = manifest.decode("utf-8") if manifest is not None else ""
        if "\x00" in text:
            raise Hostile("Helm manifest contains NUL bytes")
        if not any(line.strip() and not line.lstrip().startswith("#")
                   and line.strip() not in {"---", "..."} for line in text.splitlines()):
            raise Hostile("Helm rendered no manifests")
        return text.encode("utf-8")
    except (tarfile.TarError, EOFError, OSError, UnicodeDecodeError) as error:
        raise Hostile(f"not a readable UTF-8 Helm archive: {type(error).__name__}") from None
