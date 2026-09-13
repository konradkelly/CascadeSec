# context-agent Lambda (docs/context-agent-spec.md). Reads the repository
# snapshot to answer the questions remediation-agent's draft would otherwise
# have had to leave as assumptions, and cites file:line for every answer.
# Reuses the anthropic layer declared in lambda_mapping_agent.tf.

data "archive_file" "context_agent_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/context-agent/handler.py"
  output_path = "${path.module}/../lambda/context-agent/handler.zip"
}

resource "aws_cloudwatch_log_group" "context_agent" {
  name              = "/aws/lambda/${local.lambda_function_names.context_agent}"
  retention_in_days = 14
}

resource "aws_lambda_function" "context_agent" {
  function_name = local.lambda_function_names.context_agent
  role          = aws_iam_role.context_agent.arn

  filename         = data.archive_file.context_agent_handler.output_path
  source_code_hash = data.archive_file.context_agent_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  tracing_config {
    mode = "Active"
  }

  layers = [aws_lambda_layer_version.anthropic.arn]

  # A short tool loop: at most MAX_TOOL_CALLS model round-trips over a small
  # snapshot. remediation-agent's time reserve counts this timeout as part
  # of a finding's worst case, so a bigger number here costs findings per
  # invocation there.
  timeout     = 150
  memory_size = 512

  environment {
    variables = {
      ARTIFACTS_BUCKET     = aws_s3_bucket.artifacts.bucket
      ANTHROPIC_SECRET_ARN = aws_secretsmanager_secret.anthropic_api_key.arn
      ANTHROPIC_MODEL      = var.context_agent_model
      ENVIRONMENT          = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.context_agent,
    aws_iam_role_policy.context_agent,
  ]
}
