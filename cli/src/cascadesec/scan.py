"""`cascadesec scan` in local mode (docs/cli-spec.md §3, §5): the pipeline's
scanner, run on this machine in its own image, with no account, no model
and no network.

The scan itself is the image's: local_main.py copies what the pipeline
would scan, runs the same three tools through the same code, and labels
each finding with the controls a remote scan would choose among. This
module runs that image, and decides what the result means for an exit code.

  docker run --rm --network none --read-only --tmpfs /tmp \\
    -v <absolute path>:/src:ro --entrypoint python <image> /var/task/local_main.py /src

--network none is the guarantee that code and results never leave the
machine (§3.2). There is no fallback to a locally installed Trivy or
Checkov: a different version fires different rules, and the result would
silently disagree with the pipeline's.
"""

import json
import os
import shutil
import subprocess

from cascadesec.errors import INCOMPLETE, OK, REFUSED, SERVICE, USAGE, CliError

# The image a release pins. Overridden by CASCADESEC_SCANNER_IMAGE or
# --image, as for a locally built `cascadesec-scanner:local`. A release
# replaces the tag with the digest the Lambda was deployed with (§3.2), so
# local and pipeline results come from the same tools at the same versions.
SCANNER_IMAGE = "ghcr.io/konradkelly/cascadesec-scanner:latest"

FAIL_ON = ("critical", "high", "medium", "low", "any", "none")

# How the Docker client says the engine is not there. Linux and macOS name
# the daemon; Docker Desktop on Windows names its named pipe instead
# (measured 2026-10-22: "failed to connect to the docker API at
# npipe:////./pipe/dockerDesktopLinuxEngine"). Matched lower-case.
DAEMON_DOWN = ("cannot connect to the docker daemon", "docker daemon is not running",
               "failed to connect to the docker api", "error during connect")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def image(override, env):
    return override or env.get("CASCADESEC_SCANNER_IMAGE") or SCANNER_IMAGE


def docker_command(path, image_ref):
    return ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
            "-v", f"{path}:/src:ro", "--entrypoint", "python", image_ref,
            "/var/task/local_main.py", "/src"]


def run_scanner(path, image_ref, run=None, which=None):
    """The image's JSON result for the directory at `path`."""
    run, which = run or subprocess.run, which or shutil.which
    if not os.path.isdir(path):
        raise CliError(f"{path} is not a directory", USAGE)
    if which("docker") is None:
        raise CliError("local scans run the scanner in Docker, and `docker` is not on PATH. "
                       "Install Docker, or scan remotely once that is available (`--remote`).",
                       USAGE)
    # Absolute, so Docker mounts the directory rather than a named volume.
    result = run(docker_command(os.path.abspath(path), image_ref), capture_output=True, text=True,
                 encoding="utf-8", errors="replace")
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if any(sign in stderr.lower() for sign in DAEMON_DOWN):
            raise CliError("Docker is installed but not running; start it and scan again", USAGE)
        tail = "\n".join(stderr.splitlines()[-5:])
        raise CliError(f"the scanner image exited {result.returncode}:\n{tail}", SERVICE)
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise CliError("the scanner image printed something other than its JSON result", SERVICE) from None


def failing(findings, fail_on):
    """Findings at or above --fail-on. `any` counts every finding, including
    the ones with no severity -- which is all of checkov's, so `high`
    (the default) gates on Trivy's and KICS's severities alone."""
    if fail_on == "none":
        return []
    if fail_on == "any":
        return list(findings)
    floor = SEVERITY_RANK[fail_on]
    return [f for f in findings
            if SEVERITY_RANK.get((f.get("severity") or "").lower(), 99) <= floor]


def exit_code(result, fail_on, allow_scan_errors=False):
    """§5: 3 (incomplete) over 1 (findings at or above --fail-on) over 0.
    A clean result with a file that did not parse, or an app that was not
    run, is not clean. --allow-scan-errors downgrades 3 to the 0/1 result."""
    incomplete = bool(result.get("scan_errors") or result.get("unscanned_apps"))
    if incomplete and not allow_scan_errors:
        return INCOMPLETE
    return REFUSED if failing(result.get("findings") or [], fail_on) else OK


def summarise(result, path, image_ref, fail_on, allow_scan_errors):
    """The image's result plus what the CLI decided, for --format json."""
    gate = failing(result.get("findings") or [], fail_on)
    return {
        **result,
        "path": path,
        "scanner_image": image_ref,
        "fail_on": fail_on,
        "failing_count": len(gate),
        "exit_code": exit_code(result, fail_on, allow_scan_errors),
    }
