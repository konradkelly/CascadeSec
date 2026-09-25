# github-gateway Lambda (docs/ci-integration-spec.md §2.1, §4): the only code
# that acts as the GitHub App. Called by the state machine (fetch,
# select_files, report) and by EventBridge when an execution ends badly. No
# layers -- it speaks HTTPS with urllib and signs through KMS, so it needs
# nothing outside the runtime.

data "archive_file" "github_gateway_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/github-gateway/handler.py"
  output_path = "${path.module}/../lambda/github-gateway/handler.zip"
}

# The App's private key. Created and filled by
# scripts/import_github_app_key.py, looked up here: see
# var.github_app_key_alias. Run the script before the first apply that
# includes this file, or the plan fails here -- which is the right failure,
# since nothing below works without the key.
data "aws_kms_alias" "github_app" {
  name = var.github_app_key_alias
}

resource "aws_cloudwatch_log_group" "github_gateway" {
  name              = "/aws/lambda/${local.lambda_function_names.github_gateway}"
  retention_in_days = 14
}

resource "aws_lambda_function" "github_gateway" {
  function_name = local.lambda_function_names.github_gateway
  role          = aws_iam_role.github_gateway.arn

  filename         = data.archive_file.github_gateway_handler.output_path
  source_code_hash = data.archive_file.github_gateway_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  tracing_config {
    mode = "Active"
  }

  # fetch streams a repository tarball and keeps up to MAX_SNAPSHOT_BYTES
  # (50MB) of IaC in memory; report may page through many findings and post
  # annotations in batches. Neither is close to five minutes on a real
  # repository, but a slow codeload download should fail by the limits in
  # the handler, not by the function's clock.
  timeout     = 300
  memory_size = 1024

  environment {
    variables = {
      ARTIFACTS_BUCKET = aws_s3_bucket.artifacts.bucket
      DYNAMODB_TABLE   = aws_dynamodb_table.findings.name
      # The alias, not the key ARN: rotating the App key is a new key and a
      # moved alias (the import script), with no apply needed here.
      KMS_KEY_ID    = var.github_app_key_alias
      GITHUB_APP_ID = var.github_app_id
      # The check run's details link and the summary's dashboard link.
      DASHBOARD_URL = "https://${aws_cloudfront_distribution.dashboard.domain_name}"
      ENVIRONMENT   = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.github_gateway,
    aws_iam_role_policy.github_gateway,
  ]
}

# ---------- role ----------

resource "aws_iam_role" "github_gateway" {
  name               = "${local.lambda_function_names.github_gateway}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "github_gateway" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.github_gateway}:*"]
  }

  # Sign, and nothing else: no GetPublicKey, no DescribeKey, and there is no
  # action that returns the private key at all. This is the whole reason the
  # key is in KMS -- the role can act as the App without holding it.
  statement {
    sid       = "SignAsTheApp"
    actions   = ["kms:Sign"]
    resources = [data.aws_kms_alias.github_app.target_key_arn]
  }

  # fetch replaces the PR's snapshot; report and plan_file read it back,
  # with the fixes remediation wrote and the PR's stored patch hunks.
  statement {
    sid     = "SnapshotReadWrite"
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = [
      "${aws_s3_bucket.artifacts.arn}/scans/*",
      "${aws_s3_bucket.artifacts.arn}/github/*",
    ]
  }

  statement {
    sid       = "FixesRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/fixes/*"]
  }

  statement {
    sid       = "SnapshotList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["scans/*"]
    }
  }

  # Read only. Findings are the scanner's and the agents' to write; the
  # gateway reports them.
  statement {
    sid       = "FindingsRead"
    actions   = ["dynamodb:Query"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_gateway" {
  name   = "${local.lambda_function_names.github_gateway}-policy"
  role   = aws_iam_role.github_gateway.id
  policy = data.aws_iam_policy_document.github_gateway.json
}

# ---------- the failure backstop (spec §6.3) ----------

# An execution that fails, times out or is stopped never reaches its report
# state, and its check run would spin "in progress" on the PR for good. This
# rule hands the ending to the gateway, which completes that run -- found by
# external_id, the execution name -- as neutral with the reason. One
# mechanism for every way an execution can end badly, including a failure
# inside report itself, which a Catch in the state machine could not cover.
resource "aws_cloudwatch_event_rule" "pipeline_ended_badly" {
  name        = "${local.pipeline_name}-ended-badly"
  description = "A pipeline execution FAILED, TIMED_OUT or was ABORTED; github-gateway completes its check run"
  event_pattern = jsonencode({
    source        = ["aws.states"]
    "detail-type" = ["Step Functions Execution Status Change"]
    detail = {
      status          = ["FAILED", "TIMED_OUT", "ABORTED"]
      stateMachineArn = [aws_sfn_state_machine.pipeline.arn]
    }
  })
}

resource "aws_cloudwatch_event_target" "pipeline_ended_badly" {
  rule = aws_cloudwatch_event_rule.pipeline_ended_badly.name
  arn  = aws_lambda_function.github_gateway.arn
}

resource "aws_lambda_permission" "github_gateway_events" {
  statement_id  = "AllowInvokeFromPipelineEndedBadly"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.github_gateway.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.pipeline_ended_badly.arn
}
