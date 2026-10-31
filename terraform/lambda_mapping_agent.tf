# mapping-agent Lambda (spec §4.1, §4.4 step 4). Layer zip is built locally
# by layers/anthropic/build.sh -- run it before `terraform apply` if the zip
# is missing or stale. Shares the anthropic layer with remediation-agent once
# that Lambda exists.

# The handler, and cascadesec_core vendored beside it (portable-runtime-spec
# §8): still one artifact per function. What the zip holds, by its path in
# the zip, from where each file lives in the repository.
locals {
  mapping_agent_build = "${path.module}/../build/mapping-agent"
  mapping_agent_files = merge(
    { "handler.py" = "${path.module}/../lambda/mapping-agent/handler.py" },
    { for f in fileset("${path.module}/../core", "cascadesec_core/**/*.py") : f => "${path.module}/../core/${f}" },
  )
}

# Zipped from build/mapping-agent, which scripts/deploy.py assembles from
# those files before every plan, not from them directly. A source block
# would need no build directory, but archive_file writes its entries with
# no file mode at all and ignores output_file_mode for them, and Lambda
# documents only that it enforces the mode a zip gives (644 for code).
# source_dir writes real Unix entries, and 0644 makes the zip the same on
# Windows and Linux.
data "archive_file" "mapping_agent_handler" {
  type             = "zip"
  source_dir       = local.mapping_agent_build
  output_path      = "${path.module}/../lambda/mapping-agent/handler.zip"
  output_file_mode = "0644"

  lifecycle {
    # A build directory left from another run, or never made, would ship
    # code nobody compared. So it must hold exactly those files, byte for
    # byte, or nothing is planned.
    precondition {
      condition = (
        fileset(local.mapping_agent_build, "**") == toset(keys(local.mapping_agent_files))
        && alltrue([for rel, src in local.mapping_agent_files :
        try(filesha256("${local.mapping_agent_build}/${rel}") == filesha256(src), false)])
      )
      error_message = "build/mapping-agent is not lambda/mapping-agent/handler.py plus core/cascadesec_core. scripts/deploy.py assembles it before planning: deploy through it, not with terraform directly."
    }
  }
}

resource "aws_lambda_layer_version" "anthropic" {
  layer_name          = "${var.project}-${var.environment}-anthropic"
  filename            = "${path.module}/../layers/anthropic/anthropic-layer.zip"
  source_code_hash    = filebase64sha256("${path.module}/../layers/anthropic/anthropic-layer.zip")
  compatible_runtimes = ["python3.12"]
  description         = "anthropic Python SDK + deps under python/"
}

resource "aws_cloudwatch_log_group" "mapping_agent" {
  name              = "/aws/lambda/${local.lambda_function_names.mapping_agent}"
  retention_in_days = 14
}

resource "aws_lambda_function" "mapping_agent" {
  function_name = local.lambda_function_names.mapping_agent
  role          = aws_iam_role.mapping_agent.arn

  filename         = data.archive_file.mapping_agent_handler.output_path
  source_code_hash = data.archive_file.mapping_agent_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  # Spec §4.1: one trace from the trigger through scan -> map -> remediate,
  # including remediation-agent's synchronous self-check invoke of the
  # scanner. The X-Ray SDK is not needed for that -- Active mode traces the
  # invocation and the boto3 calls it makes.
  tracing_config {
    mode = "Active"
  }

  layers = [aws_lambda_layer_version.anthropic.arn]

  # One model call per finding, ~3s each, and the handler yields to the
  # state machine before this runs out (FINDING_TIME_RESERVE_SECONDS). The
  # timeout is how much of a PR one pass maps, not a ceiling on the PR:
  # 120s held 38 of a 47-candidate scan and failed the pipeline
  # (2026-09-18), so it is longer now, and the yield is what makes the
  # length not matter.
  timeout     = 300
  memory_size = 512

  environment {
    variables = {
      DYNAMODB_TABLE       = aws_dynamodb_table.findings.name
      ARTIFACTS_BUCKET     = aws_s3_bucket.artifacts.bucket
      # Dimension on the token-usage metrics the handler emits (observability.tf).
      ENVIRONMENT          = var.environment
      # Time a finding needs before it starts: one model call, allowing
      # for a slow one. See mapping-agent's handler.
      FINDING_TIME_RESERVE_SECONDS = "30"
      ANTHROPIC_SECRET_ARN = aws_secretsmanager_secret.anthropic_api_key.arn
      ANTHROPIC_MODEL      = var.mapping_agent_model
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.mapping_agent,
    aws_iam_role_policy.mapping_agent,
  ]
}
