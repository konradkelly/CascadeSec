# iac-scanner Lambda (spec §4.1, §4.4 step 3), packaged as a container
# image since 2026-09-13. The image is built and pushed by
# lambda/iac-scanner/build-image.sh; this file resolves what was pushed.
#
# Why an image (spec §4.3, revised): the zip-plus-layers packaging reached
# Lambda's 250MB unzipped ceiling when Trivy replaced tfsec -- 247MB of 250,
# with the next bump of Trivy or checkov certain to fail the deploy. An image
# is allowed 10GB. Everything else about the function is unchanged: same
# handler, role, Step Functions integration and alarms. The other functions
# stay zip-packaged; they are small and the anthropic layer fits with room.

resource "aws_ecr_repository" "iac_scanner" {
  name = local.lambda_function_names.iac_scanner
  # `latest` is re-pointed on every push; the digest below is what pins the
  # function, so mutability here costs nothing.
  image_tag_mutability = "MUTABLE"
  # Dev: let `terraform destroy` take the images with it.
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

# The tag per build is the git commit, so old images are reproducible; keep
# a few for rollback and let the rest expire.
resource "aws_ecr_lifecycle_policy" "iac_scanner" {
  repository = aws_ecr_repository.iac_scanner.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the last 5 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}

# Resolves `latest` to a digest at plan time, so a push followed by an apply
# rolls the function, and an apply with nothing pushed changes nothing. On a
# first deploy this fails until build-image.sh has run -- see the order in
# that script's header.
data "aws_ecr_image" "iac_scanner" {
  repository_name = aws_ecr_repository.iac_scanner.name
  image_tag       = "latest"
}

resource "aws_cloudwatch_log_group" "iac_scanner" {
  name              = "/aws/lambda/${local.lambda_function_names.iac_scanner}"
  retention_in_days = 14
}

resource "aws_lambda_function" "iac_scanner" {
  function_name = local.lambda_function_names.iac_scanner
  role          = aws_iam_role.iac_scanner.arn

  package_type = "Image"
  # By digest, not tag: the function is pinned to exactly the image the plan
  # showed, and Lambda's own image cache keys on it.
  image_uri = "${aws_ecr_repository.iac_scanner.repository_url}@${data.aws_ecr_image.iac_scanner.image_digest}"

  # Spec §4.1: one trace from the trigger through scan -> map -> remediate,
  # including remediation-agent's synchronous self-check invoke of the
  # scanner. The X-Ray SDK is not needed for that -- Active mode traces the
  # invocation and the boto3 calls it makes.
  tracing_config {
    mode = "Active"
  }

  # Checkov is the dominant cost, and it is CPU-bound: its import, and
  # then a graph rebuild for every instantiation of a module. Lambda's CPU
  # share scales with memory (~1 vCPU at 1769 MB), and at 1024 MB
  # terraform-aws-modules/terraform-aws-vpc -- 77 files, thirteen examples
  # each instantiating the root module -- took 265s of the 300s allowed
  # (corpus/external/README.md, 2026-09-18) for what is 60s of CPU in the
  # image locally. 3008 MB is ~1.7 vCPU: about the same GB-seconds per
  # scan, a third of the wall time, and room for module repositories
  # this size to finish at all.
  timeout     = 300
  memory_size = 3008

  environment {
    variables = {
      DYNAMODB_TABLE   = aws_dynamodb_table.findings.name
      ARTIFACTS_BUCKET = aws_s3_bucket.artifacts.bucket
      # Dimension on the metrics the handler emits (observability.tf).
      ENVIRONMENT = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.iac_scanner,
    aws_iam_role_policy.iac_scanner,
  ]
}

output "scanner_ecr_repository_url" {
  value = aws_ecr_repository.iac_scanner.repository_url
}
