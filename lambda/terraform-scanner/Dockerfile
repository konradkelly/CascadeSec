# syntax=docker/dockerfile:1
# terraform-scanner as a container image (spec §4.3, revised 2026-09-13).
#
# The zip-plus-layers packaging hit Lambda's 250MB unzipped ceiling the day
# Trivy replaced tfsec: Trivy's binary (~161MB) and checkov (~86MB) left 7MB
# of headroom, and the next bump of either would have failed the deploy. An
# image is allowed 10GB. Nothing else about the function changes -- same
# handler, same role, same Step Functions integration, same alarms -- and the
# on-disk layout is the one the layers used (/opt/bin/trivy, /opt/python), so
# handler.py is untouched.
#
# Built and pushed by build-image.sh; terraform/lambda_terraform_scanner.tf
# resolves the pushed image by digest.

FROM public.ecr.aws/lambda/python:3.12

# Both pins are what the eval numbers were measured against (corpus/eval/
# README.md). Bumping either changes what fires; re-run the eval.
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_SHA256=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
ARG CHECKOV_VERSION=3.3.16

# Trivy: the static binary, with its checks bundle embedded. The handler runs
# it with --skip-check-update, so this version's checks are the rule set.
# Extracted with Python: the Lambda base image is Amazon Linux minimal and
# ships no tar.
RUN curl -sL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
 && echo "${TRIVY_SHA256}  /tmp/trivy.tgz" | sha256sum -c - \
 && mkdir -p /opt/bin \
 && python -c "import tarfile; tarfile.open('/tmp/trivy.tgz').extract('trivy', '/opt/bin')" \
 && rm /tmp/trivy.tgz \
 && chmod +x /opt/bin/trivy

# checkov, into the same path the layer used. The same strip as the old
# layer build: numpy is not needed for Terraform scanning (verified
# empirically), and the Lambda base image already carries boto3. Not for the
# size ceiling any more -- for a smaller image to pull on a cold start.
# (Python again: no find in the base image either.)
RUN pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" -t /opt/python
RUN <<'EOF'
python - <<'PY'
import glob, os, shutil
root = "/opt/python"
for pattern in ("numpy", "numpy.libs", "numpy-*.dist-info", "botocore", "botocore-*.dist-info",
                "boto3", "boto3-*.dist-info", "s3transfer", "s3transfer-*.dist-info"):
    for path in glob.glob(os.path.join(root, pattern)):
        shutil.rmtree(path, ignore_errors=True)
for dirpath, dirnames, _ in os.walk(root):
    for name in list(dirnames):
        if name in ("__pycache__", "tests"):
            shutil.rmtree(os.path.join(dirpath, name), ignore_errors=True)
            dirnames.remove(name)
PY
EOF

COPY handler.py ${LAMBDA_TASK_ROOT}/

CMD ["handler.handler"]
