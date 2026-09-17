#!/usr/bin/env bash
# Builds the iac-scanner image and pushes it to the ECR repository
# Terraform created, tagged `latest` and with the git commit. Terraform then
# resolves `latest` to its digest (data.aws_ecr_image), so an apply after a
# push rolls the function to the new image and an apply without one changes
# nothing.
#
# First deploy, in order: the repository has to exist before the push, and
# the image before the function.
#   terraform -chdir=terraform apply -target=aws_ecr_repository.iac_scanner
#   lambda/iac-scanner/build-image.sh
#   terraform -chdir=terraform apply
# Every deploy after that: build-image.sh, then apply.
#
# Usage: ./build-image.sh [repository-url]
# If repository-url is omitted, reads it from `terraform output`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

REPOSITORY="${1:-}"
if [ -z "$REPOSITORY" ]; then
  REPOSITORY="$(cd "${REPO_DIR}/terraform" && terraform output -raw scanner_ecr_repository_url)"
fi
REGISTRY="${REPOSITORY%%/*}"
REGION="$(echo "$REGISTRY" | sed -E 's/^[0-9]+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$/\1/')"
COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD)"

aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY"

# Lambda needs a single-platform image manifest: no attestation manifests
# (--provenance=false) and linux/amd64, whatever the host is.
docker build \
  --platform linux/amd64 \
  --provenance=false \
  -t "${REPOSITORY}:latest" \
  -t "${REPOSITORY}:${COMMIT}" \
  "$SCRIPT_DIR"

docker push "${REPOSITORY}:latest"
docker push "${REPOSITORY}:${COMMIT}"

echo "Pushed ${REPOSITORY}:latest (${COMMIT})"
