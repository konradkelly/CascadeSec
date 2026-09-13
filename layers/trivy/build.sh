#!/usr/bin/env bash
# Builds the Trivy Lambda layer: downloads the pinned linux-amd64 release
# tarball, verifies its checksum, and lays the binary out under bin/ (Lambda
# adds /opt/bin to PATH automatically for layers with that structure).
#
# Trivy replaced tfsec (spec §8.2 item 6): same Terraform engine, but tfsec
# stopped taking rule changes in 2025 and its last release is a CVE bump. The
# checks bundle is embedded in the binary, and the scanner runs with
# --skip-check-update, so the rule set is pinned to TRIVY_VERSION -- a scan is
# reproducible by re-running this version on the same file, which is what
# §8.1's admission rule needs. Bumping the version changes what fires.
#
# Size: the binary is ~161MB uncompressed. With the checkov layer (~86MB) that
# is ~247MB against Lambda's 250MB unzipped function+layers ceiling. A Trivy
# or checkov bump that grows either by more than ~7MB will fail to deploy;
# the fallback at that point is a container-image function, not a bigger
# layer.
#
# Usage: ./build.sh
# Output: ./bin/trivy, ./trivy-layer.zip

set -euo pipefail

TRIVY_VERSION="0.74.0"
# From trivy_${TRIVY_VERSION}_checksums.txt on the release page.
TRIVY_SHA256="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

rm -rf bin
mkdir -p bin

TARBALL="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
curl -sL -o "${TARBALL}" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TARBALL}"

echo "${TRIVY_SHA256}  ${TARBALL}" | sha256sum -c -
# Only the binary; the tarball also carries README, LICENSE and report templates.
tar -xzf "${TARBALL}" -C bin trivy
rm -f "${TARBALL}"
chmod +x bin/trivy

python3 -c "
import zipfile, os
out = 'trivy-layer.zip'
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk('bin'):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, '.')
            zi = zipfile.ZipInfo(rel.replace(os.sep, '/'))
            zi.external_attr = 0o100755 << 16
            with open(full, 'rb') as fh:
                zf.writestr(zi, fh.read(), zipfile.ZIP_DEFLATED)
"

echo "Built trivy-layer.zip ($(du -h trivy-layer.zip | cut -f1))"
