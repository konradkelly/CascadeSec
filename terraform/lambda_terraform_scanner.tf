# terraform-scanner Lambda (spec §4.1, §4.4 step 3). Layer zips are built
# locally by layers/trivy/build.sh and layers/checkov/build.sh -- run those
# before `terraform apply` if either layer's zip is missing or stale.

data "archive_file" "terraform_scanner_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/terraform-scanner/handler.py"
  output_path = "${path.module}/../lambda/terraform-scanner/handler.zip"
}

# Replaced tfsec on 2026-09-12 (spec §8.2 item 6). The binary is ~161MB
# unzipped, and with checkov's ~86MB the function sits ~7MB under Lambda's
# 250MB function+layers ceiling -- see layers/trivy/build.sh before bumping
# either.
resource "aws_lambda_layer_version" "trivy" {
  layer_name          = "${var.project}-${var.environment}-trivy"
  filename            = "${path.module}/../layers/trivy/trivy-layer.zip"
  source_code_hash    = filebase64sha256("${path.module}/../layers/trivy/trivy-layer.zip")
  compatible_runtimes = ["python3.12"]
  description         = "Trivy static binary (linux-amd64) under bin/, checks bundle embedded"
}

resource "aws_lambda_layer_version" "checkov" {
  layer_name          = "${var.project}-${var.environment}-checkov"
  filename            = "${path.module}/../layers/checkov/checkov-layer.zip"
  source_code_hash    = filebase64sha256("${path.module}/../layers/checkov/checkov-layer.zip")
  compatible_runtimes = ["python3.12"]
  description         = "Checkov + deps (numpy, boto3/botocore stripped) under python/"
}

resource "aws_cloudwatch_log_group" "terraform_scanner" {
  name              = "/aws/lambda/${local.lambda_function_names.terraform_scanner}"
  retention_in_days = 14
}

resource "aws_lambda_function" "terraform_scanner" {
  function_name = local.lambda_function_names.terraform_scanner
  role          = aws_iam_role.terraform_scanner.arn

  filename         = data.archive_file.terraform_scanner_handler.output_path
  source_code_hash = data.archive_file.terraform_scanner_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  # Spec §4.1: one trace from the trigger through scan -> map -> remediate,
  # including remediation-agent's synchronous self-check invoke of the
  # scanner. The X-Ray SDK is not needed for that -- Active mode traces the
  # invocation and the boto3 calls it makes.
  tracing_config {
    mode = "Active"
  }

  layers = [
    aws_lambda_layer_version.checkov.arn,
    aws_lambda_layer_version.trivy.arn,
  ]

  # Checkov's own module import is the dominant cost (~50-100s observed
  # locally, see handler.py) -- generous timeout and higher memory (which
  # also buys more CPU on Lambda) both compensate for that until the
  # in-process Runner API switch lands.
  timeout     = 300
  memory_size = 1024

  environment {
    variables = {
      DYNAMODB_TABLE   = aws_dynamodb_table.findings.name
      ARTIFACTS_BUCKET = aws_s3_bucket.artifacts.bucket
      # Dimension on the metrics the handler emits (observability.tf).
      ENVIRONMENT = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.terraform_scanner,
    aws_iam_role_policy.terraform_scanner,
  ]
}
