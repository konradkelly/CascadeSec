# syntax=docker/dockerfile:1
# The docker_image pre-commit hook's image (docs/cli-spec.md §7): the
# scanner image, unchanged, with the CLI on top. pre-commit runs it with the
# changed files, `cascadesec hook` scans them in-process with the scanner's
# own local_main (CASCADESEC_IN_IMAGE), and judges the result with the same
# code as the installed CLI's hook, so the two hooks cannot disagree.
#
# A separate image, not the scanner's, so that a change to the hook never
# rebuilds the image the Lambda runs, and the Lambda's ECR scan never
# reports what only the hook needs.
#
# Built FROM the digest the CLI pins (cascadesec/scan.py SCANNER_IMAGE;
# tests/test_hook.py holds the two equal), so the hook scans with exactly
# the tools the Lambda runs. build-image.sh --ghcr builds it on each scanner
# publish. Locally, on a locally built scanner:
#   docker build --build-arg SCANNER_IMAGE=cascadesec-scanner:local -t cascadesec-hook:local cli
ARG SCANNER_IMAGE=ghcr.io/konradkelly/cascadesec-scanner@sha256:a60b6aaae929ed7799ca9869b427763bd64efa0aee1013bc2a09f1198ad50c8b
FROM ${SCANNER_IMAGE}
ARG SCANNER_IMAGE

# git: the hook judges a change by scanning the version before it too, which
# it reads from the mounted repository's history (cascadesec/history.py). A
# 64 MB layer, with the package cache removed, that the scanner image and so
# the Lambda go without. safe.directory: pre-commit mounts the repository at
# /src, owned by whoever owns it on the host, and the hook only reads it.
# Before the CLI, so a CLI change does not reinstall it.
RUN dnf install -y git-core \
 && dnf clean all && rm -rf /var/cache/dnf \
 && git config --system --add safe.directory '*'

# --no-deps: the CLI's one dependency is keyring, for a signed-in session,
# which a hook never opens. It would bring cryptography, cffi and Secret
# Service; tests/test_hook.py runs the hook with keyring unimportable to
# keep that true. Bind-mounted rather than copied, so no layer keeps the
# source.
RUN --mount=type=bind,target=/tmp/cascadesec-cli,rw \
    pip install --no-cache-dir --no-deps /tmp/cascadesec-cli

# CASCADESEC_SCANNER_IMAGE names the scanner this image is built on, so the
# hook's output and a baseline's image check name it, as the installed CLI
# names the image it starts.
ENV CASCADESEC_IN_IMAGE=1 \
    CASCADESEC_SCANNER_IMAGE=${SCANNER_IMAGE}
LABEL io.cascadesec.scanner-image=${SCANNER_IMAGE}

# The image is the hook: pre-commit appends the file names. CMD is cleared
# so the scanner's handler.handler is never taken for one.
ENTRYPOINT ["python", "-m", "cascadesec", "hook"]
CMD []
