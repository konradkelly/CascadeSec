#!/usr/bin/env bash
# Builds the sandbox's node22 image and pushes it to the ECR repository
# terraform/sandbox created, tagged `latest` and with the git commit.
# terraform/sandbox resolves `latest` to its digest (ecs.tf), so an apply
# after a push moves both task definitions to the new image.
#
# First deploy, in order: the repository before the push, the image before
# the task definitions.
#   terraform -chdir=terraform/sandbox apply -target=aws_ecr_repository.node22
#   sandbox/image/build-image.sh
#   python scripts/sandbox.py up
# After that: build-image.sh, then `scripts/sandbox.py up` (an apply), and
# `scripts/sandbox.py leak-test` -- every image change re-earns its pass.
#
# Usage: ./build-image.sh [repository-url]
# If repository-url is omitted, reads it from `terraform output`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

REPOSITORY="${1:-}"
if [ -z "$REPOSITORY" ]; then
  REPOSITORY="$(terraform -chdir="${REPO_DIR}/terraform/sandbox" output -raw ecr_repository_url)"
fi
REGISTRY="${REPOSITORY%%/*}"
REGION="$(echo "$REGISTRY" | sed -E 's/^[0-9]+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$/\1/')"
COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD)"

aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY"

# Fargate needs a single-platform manifest for the task's architecture.
docker build \
  --platform linux/amd64 \
  --provenance=false \
  -t "${REPOSITORY}:latest" \
  -t "${REPOSITORY}:${COMMIT}" \
  "$SCRIPT_DIR"

docker push "${REPOSITORY}:latest"
docker push "${REPOSITORY}:${COMMIT}"

echo "Pushed ${REPOSITORY}:latest (${COMMIT})"
