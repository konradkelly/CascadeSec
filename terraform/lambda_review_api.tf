# review-api Lambda (spec §4.1, §4.4 step 6). No layers -- boto3 is already in
# the Lambda Python runtime. It calls nothing else, except to hand a commit
# request to github-committer (write-back-spec §3).

data "archive_file" "review_api_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/review-api/handler.py"
  output_path = "${path.module}/../lambda/review-api/handler.zip"
}

resource "aws_cloudwatch_log_group" "review_api" {
  name              = "/aws/lambda/${local.lambda_function_names.review_api}"
  retention_in_days = 14
}

resource "aws_lambda_function" "review_api" {
  function_name = local.lambda_function_names.review_api
  role          = aws_iam_role.review_api.arn

  filename         = data.archive_file.review_api_handler.output_path
  source_code_hash = data.archive_file.review_api_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  # Spec §4.1: one trace from the trigger through scan -> map -> remediate,
  # including remediation-agent's synchronous self-check invoke of the
  # scanner. The X-Ray SDK is not needed for that -- Active mode traces the
  # invocation and the boto3 calls it makes.
  tracing_config {
    mode = "Active"
  }

  # Interactive request path -- a dashboard user is waiting on every call, and
  # the work is a couple of DynamoDB round-trips. Unlike the agent Lambdas this
  # wants low latency, not a long ceiling.
  timeout     = 10
  memory_size = 256

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.findings.name
      # A reviewer's edit is the corrected file, and the diff is computed here
      # against the fix's base -- both live in the artifacts bucket.
      ARTIFACTS_BUCKET = aws_s3_bucket.artifacts.bucket
      # Dimension on the metrics the handler emits (observability.tf).
      ENVIRONMENT = var.environment
      # Where a commit request goes (write-back-spec §3). Empty while
      # write-back is not deployed, and a request is then refused with 503.
      COMMITTER_FUNCTION_NAME = local.write_back_enabled ? local.lambda_function_names.github_committer : ""
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.review_api,
    aws_iam_role_policy.review_api,
  ]
}
