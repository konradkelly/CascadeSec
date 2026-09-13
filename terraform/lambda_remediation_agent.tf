# remediation-agent Lambda (spec §4.1, §4.4 step 5). Reuses the anthropic layer
# declared in lambda_mapping_agent.tf rather than declaring a second copy --
# that layer's description already anticipated this second consumer.

data "archive_file" "remediation_agent_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/remediation-agent/handler.py"
  output_path = "${path.module}/../lambda/remediation-agent/handler.zip"
}

resource "aws_cloudwatch_log_group" "remediation_agent" {
  name              = "/aws/lambda/${local.lambda_function_names.remediation_agent}"
  retention_in_days = 14
}

resource "aws_lambda_function" "remediation_agent" {
  function_name = local.lambda_function_names.remediation_agent
  role          = aws_iam_role.remediation_agent.arn

  filename         = data.archive_file.remediation_agent_handler.output_path
  source_code_hash = data.archive_file.remediation_agent_handler.output_base64sha256
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

  # Each finding is an Anthropic call plus a synchronous terraform-scanner
  # invoke that is itself allowed 300s, so even the max timeout fits only a
  # handful. The pipeline (step_functions.tf) invokes this once per file and
  # the handler yields with a continuation before the clock runs out, so a
  # file of any size is a sequence of invocations rather than one that does
  # not fit. The number here just decides how many findings each one does.
  timeout = 900
  # I/O-bound, so no reason to buy the extra CPU terraform-scanner needs.
  memory_size = 512

  environment {
    variables = {
      DYNAMODB_TABLE       = aws_dynamodb_table.findings.name
      ARTIFACTS_BUCKET     = aws_s3_bucket.artifacts.bucket
      ANTHROPIC_SECRET_ARN = aws_secretsmanager_secret.anthropic_api_key.arn
      ANTHROPIC_MODEL      = var.remediation_agent_model
      # The handler needs the scanner's name to invoke it for the self-check.
      # Wired from the resource rather than reconstructed from locals so the
      # dependency is explicit in the graph.
      TERRAFORM_SCANNER_FUNCTION_NAME = aws_lambda_function.terraform_scanner.function_name
      # A draft may ask the repository questions before it is final.
      CONTEXT_AGENT_FUNCTION_NAME = aws_lambda_function.context_agent.function_name
      # Time the handler leaves on the clock before starting another finding:
      # the scanner's timeout, context-agent's timeout, and two model calls
      # (the draft and, when questions were asked, the redraft) at a worst
      # case of 120s each. Tied to the other functions' timeouts so the
      # numbers cannot drift apart silently.
      FINDING_TIME_RESERVE_SECONDS = aws_lambda_function.terraform_scanner.timeout + aws_lambda_function.context_agent.timeout + 240
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.remediation_agent,
    aws_iam_role_policy.remediation_agent,
  ]
}
