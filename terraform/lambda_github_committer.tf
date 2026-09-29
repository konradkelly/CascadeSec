# github-committer Lambda (docs/write-back-spec.md): commits a PR's approved
# fixes to its branch, as the write-back App "CascadeSec Fixes". Invoked
# asynchronously by review-api once a committer has asked, and by
# EventBridge when an invocation has failed for good. API Gateway cannot
# reach it: review-api records the request and hands it over, and never
# signs anything itself (write-back-spec §2, W1).
#
# Everything here is counted on local.write_back_enabled (iam.tf), so an
# apply before the writer App is registered and its key imported deploys
# none of it, rather than failing on the key lookup below.

data "archive_file" "github_committer_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/github-committer/handler.py"
  output_path = "${path.module}/../lambda/github-committer/handler.zip"
}

# The writer App's key, imported by scripts/import_github_app_key.py --alias.
# A second App rather than Contents write on the first (write-back-spec §4,
# W2): github-gateway parses repository tarballs, and whoever can sign as an
# App can ask for any permission it holds. So the key that can write is one
# github-gateway cannot sign with.
data "aws_kms_alias" "github_writer_app" {
  count = local.write_back_enabled ? 1 : 0
  name  = var.github_writer_app_key_alias
}

resource "aws_cloudwatch_log_group" "github_committer" {
  count             = local.write_back_enabled ? 1 : 0
  name              = "/aws/lambda/${local.lambda_function_names.github_committer}"
  retention_in_days = 14
}

resource "aws_lambda_function" "github_committer" {
  count         = local.write_back_enabled ? 1 : 0
  function_name = local.lambda_function_names.github_committer
  role          = aws_iam_role.github_committer[0].arn

  filename         = data.archive_file.github_committer_handler.output_path
  source_code_hash = data.archive_file.github_committer_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  tracing_config {
    mode = "Active"
  }

  # A few GitHub calls per file -- a tree walk, the blob, then one blob,
  # tree, commit and ref update for the lot -- and a DynamoDB write per
  # committed fix. Seconds on a real PR; the ceiling is for GitHub being
  # slow, which should fail as a timed-out request, not a killed function.
  timeout     = 300
  memory_size = 256

  environment {
    variables = {
      ARTIFACTS_BUCKET = aws_s3_bucket.artifacts.bucket
      DYNAMODB_TABLE   = aws_dynamodb_table.findings.name
      # The alias, as github-gateway's is: rotating the key is a new key
      # and a moved alias, with no apply needed here.
      KMS_KEY_ID    = var.github_writer_app_key_alias
      GITHUB_APP_ID = var.github_writer_app_id
      # The commit message's link back to the review.
      DASHBOARD_URL = "https://${aws_cloudfront_distribution.dashboard.domain_name}"
      ENVIRONMENT   = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.github_committer,
    aws_iam_role_policy.github_committer,
  ]
}

# ---------- role ----------

resource "aws_iam_role" "github_committer" {
  count              = local.write_back_enabled ? 1 : 0
  name               = "${local.lambda_function_names.github_committer}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "github_committer" {
  count = local.write_back_enabled ? 1 : 0

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.github_committer}:*"]
  }

  # Sign as the writer App, and nothing else -- the same shape as
  # github-gateway's grant on its own key, and the only role with this one.
  statement {
    sid       = "SignAsTheWriterApp"
    actions   = ["kms:Sign"]
    resources = [data.aws_kms_alias.github_writer_app[0].target_key_arn]
  }

  # Read the request, the PR's GitHub identity, its findings and their
  # events; mark the request, the committed fixes, and write a "committed"
  # event per fix. GitHub PRs' partitions only: a committer has no reason
  # to touch a manual run's records.
  statement {
    sid       = "FindingsAndRequests"
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:UpdateItem", "dynamodb:PutItem"]
    resources = [aws_dynamodb_table.findings.arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["PR#gh-*"]
    }
  }

  # The fixes' corrected files, which are what gets committed. No scans/:
  # the head is read from GitHub, never from a snapshot that may be stale.
  statement {
    sid       = "FixesRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/fixes/*"]
  }

  # The on-failure destination below delivers with this role.
  statement {
    sid       = "FailureDestination"
    actions   = ["events:PutEvents"]
    resources = ["arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:event-bus/default"]
  }

  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_committer" {
  count  = local.write_back_enabled ? 1 : 0
  name   = "${local.lambda_function_names.github_committer}-policy"
  role   = aws_iam_role.github_committer[0].id
  policy = data.aws_iam_policy_document.github_committer[0].json
}

# ---------- retries, and the failure backstop ----------

# Lambda retries a failed async invoke twice. The handler is written for it
# (write-back-spec §10): the request moves to "committing" conditionally, and
# a retry that finds it there looks for its own trailer on the branch before
# doing anything. An hour is long enough for a GitHub outage to pass, and
# short enough that nobody is still watching a request that old.
resource "aws_lambda_function_event_invoke_config" "github_committer" {
  count                        = local.write_back_enabled ? 1 : 0
  function_name                = aws_lambda_function.github_committer[0].function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600

  # When the retries are spent, the request would sit at "committing" and
  # the dashboard would poll it forever. The failure goes to EventBridge,
  # and the rule below hands it back to the committer, which marks the
  # request failed -- the pattern github-gateway's backstop uses.
  destination_config {
    on_failure {
      destination = "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:event-bus/default"
    }
  }
}

resource "aws_cloudwatch_event_rule" "commit_failed" {
  count       = local.write_back_enabled ? 1 : 0
  name        = "${local.lambda_function_names.github_committer}-failed"
  description = "A github-committer invocation failed after its retries; the committer marks the request failed"
  event_pattern = jsonencode({
    source        = ["lambda"]
    "detail-type" = ["Lambda Function Invocation Result - Failure"]
    # The function ARN, with or without a version qualifier.
    resources = [{ prefix = aws_lambda_function.github_committer[0].arn }]
  })
}

resource "aws_cloudwatch_event_target" "commit_failed" {
  count = local.write_back_enabled ? 1 : 0
  rule  = aws_cloudwatch_event_rule.commit_failed[0].name
  arn   = aws_lambda_function.github_committer[0].arn
}

resource "aws_lambda_permission" "github_committer_events" {
  count         = local.write_back_enabled ? 1 : 0
  statement_id  = "AllowInvokeFromCommitFailed"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.github_committer[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.commit_failed[0].arn
}
