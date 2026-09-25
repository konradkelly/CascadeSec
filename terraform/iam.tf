# Roles for the v1 Lambdas (spec §4.1, §4.4). Function names are fixed here so
# permissions can be scoped ahead of the Lambda resources themselves, which are
# created in a later pass. webhook-receiver is v3's (docs/ci-integration-spec.md);
# there is no SQS role because v3 dropped the queue (spec §1).
locals {
  lambda_function_names = {
    iac_scanner       = "${var.project}-${var.environment}-iac-scanner"
    mapping_agent     = "${var.project}-${var.environment}-mapping-agent"
    remediation_agent = "${var.project}-${var.environment}-remediation-agent"
    context_agent     = "${var.project}-${var.environment}-context-agent"
    review_api        = "${var.project}-${var.environment}-review-api"
    webhook_receiver  = "${var.project}-${var.environment}-webhook-receiver"
    github_gateway    = "${var.project}-${var.environment}-github-gateway"
  }
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ---------- iac-scanner ----------
# Runs Trivy + Checkov against snapshots in S3, writes raw findings to DynamoDB.

resource "aws_iam_role" "iac_scanner" {
  name               = "${local.lambda_function_names.iac_scanner}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "iac_scanner" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.iac_scanner}:*"]
  }

  statement {
    sid     = "ScanArtifactsReadWrite"
    actions = ["s3:GetObject", "s3:PutObject"]
    # fixes/ because a self-check scans a fix's corrected file from there.
    resources = [
      "${aws_s3_bucket.artifacts.arn}/scans/*",
      "${aws_s3_bucket.artifacts.arn}/fixes/*",
    ]
  }

  # ListObjectsV2 (used to enumerate a scan's .tf files by prefix) is a
  # bucket-level action -- it must target the bucket ARN itself, not an
  # object path, so it can't be folded into ScanArtifactsReadWrite above.
  statement {
    sid       = "ScanArtifactsList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["scans/*", "fixes/*"]
    }
  }

  statement {
    sid = "FindingsReadWrite"
    # BatchWriteItem is what boto3's Table.batch_writer() actually calls under
    # the hood -- easy to miss since the handler code only mentions put_item.
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:BatchWriteItem"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  # Active tracing needs the function to be able to ship its segments.
  # Region-scoped resource ARNs don't exist for these two actions.
  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "iac_scanner" {
  name   = "${local.lambda_function_names.iac_scanner}-policy"
  role   = aws_iam_role.iac_scanner.id
  policy = data.aws_iam_policy_document.iac_scanner.json
}

# ---------- mapping-agent ----------
# Reads raw findings + control corpus, calls Anthropic API, writes control-mapped findings.

resource "aws_iam_role" "mapping_agent" {
  name               = "${local.lambda_function_names.mapping_agent}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "mapping_agent" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.mapping_agent}:*"]
  }

  statement {
    sid       = "ControlCorpusRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/corpus/*"]
  }

  statement {
    sid       = "FindingsReadWrite"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid       = "AnthropicApiKeyRead"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.anthropic_api_key.arn]
  }

  # Active tracing needs the function to be able to ship its segments.
  # Region-scoped resource ARNs don't exist for these two actions.
  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "mapping_agent" {
  name   = "${local.lambda_function_names.mapping_agent}-policy"
  role   = aws_iam_role.mapping_agent.id
  policy = data.aws_iam_policy_document.mapping_agent.json
}

# ---------- remediation-agent ----------
# Drafts a diff via Anthropic API, then invokes iac-scanner to self-check it.

resource "aws_iam_role" "remediation_agent" {
  name               = "${local.lambda_function_names.remediation_agent}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "remediation_agent" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.remediation_agent}:*"]
  }

  statement {
    sid       = "FindingsReadWrite"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid       = "AnthropicApiKeyRead"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.anthropic_api_key.arn]
  }

  statement {
    sid     = "InvokeScannerAndContext"
    actions = ["lambda:InvokeFunction"]
    # The scanner for the self-check; context-agent for a draft's questions.
    resources = [
      "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.lambda_function_names.iac_scanner}",
      "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.lambda_function_names.context_agent}",
    ]
  }

  statement {
    sid     = "SnapshotsAndFixContent"
    actions = ["s3:GetObject", "s3:PutObject"]
    # scans/ for the pristine snapshot a file's first fix is drafted against;
    # fixes/ to write each fix's corrected file and to read the last accepted
    # one back as the base for the next chain.
    resources = [
      "${aws_s3_bucket.artifacts.arn}/scans/*",
      "${aws_s3_bucket.artifacts.arn}/fixes/*",
    ]
  }

  # Active tracing needs the function to be able to ship its segments.
  # Region-scoped resource ARNs don't exist for these two actions.
  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "remediation_agent" {
  name   = "${local.lambda_function_names.remediation_agent}-policy"
  role   = aws_iam_role.remediation_agent.id
  policy = data.aws_iam_policy_document.remediation_agent.json
}

# ---------- context-agent ----------
# Reads the repository snapshot and calls the Anthropic API. Nothing else: no
# DynamoDB, no writes -- it answers questions and cites; it decides nothing.
resource "aws_iam_role" "context_agent" {
  name               = "${local.lambda_function_names.context_agent}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "context_agent" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.context_agent}:*"]
  }
  # The pristine snapshot only. A draft's questions are about the rest of
  # the repository, which no fix changes; the finding's own file is already
  # in the model's context via remediation-agent.
  statement {
    sid       = "SnapshotRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/scans/*"]
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
  statement {
    sid       = "AnthropicApiKeyRead"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.anthropic_api_key.arn]
  }
  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "context_agent" {
  name   = "${local.lambda_function_names.context_agent}-policy"
  role   = aws_iam_role.context_agent.id
  policy = data.aws_iam_policy_document.context_agent.json
}

# ---------- review-api ----------
# CRUD behind API Gateway for the dashboard: list findings, get diff, post approve/reject.

resource "aws_iam_role" "review_api" {
  name               = "${local.lambda_function_names.review_api}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "review_api" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.review_api}:*"]
  }

  statement {
    sid       = "FindingsAndAuditLogReadWrite"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  # An edit is diffed against the fix's base: the PR's pristine snapshot
  # (scans/<pr_id>/) for a file's first fix, otherwise a prerequisite's
  # corrected file (fixes/). The write is only ever a fix's own corrected
  # file. docs/reviewer-edit-spec.md §4.
  statement {
    sid     = "ReadFixBases"
    actions = ["s3:GetObject"]
    resources = [
      "${aws_s3_bucket.artifacts.arn}/scans/*",
      "${aws_s3_bucket.artifacts.arn}/fixes/*",
    ]
  }

  statement {
    sid       = "WriteEditedFixContent"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/fixes/*"]
  }

  # Active tracing needs the function to be able to ship its segments.
  # Region-scoped resource ARNs don't exist for these two actions.
  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "review_api" {
  name   = "${local.lambda_function_names.review_api}-policy"
  role   = aws_iam_role.review_api.id
  policy = data.aws_iam_policy_document.review_api.json
}

# ---------- webhook-receiver ----------
# The only unauthenticated, internet-facing function: it verifies a GitHub
# delivery's signature and starts one pipeline execution. So it gets the
# webhook secret and StartExecution on the one state machine, and nothing
# else -- no S3, no DynamoDB, and above all not the App private key. A forged
# request that got past it could start an execution, and nothing more
# (docs/ci-integration-spec.md §2.1).

resource "aws_iam_role" "webhook_receiver" {
  name               = "${local.lambda_function_names.webhook_receiver}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "webhook_receiver" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.webhook_receiver}:*"]
  }

  statement {
    sid       = "WebhookSecretRead"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.github_webhook_secret.arn]
  }

  # StartExecution only. A redelivery is made idempotent by the execution
  # name (ExecutionAlreadyExists), so the function never needs to list or
  # describe executions to find out what already ran.
  statement {
    sid       = "StartPipeline"
    actions   = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.pipeline.arn]
  }

  # Active tracing needs the function to be able to ship its segments.
  # Region-scoped resource ARNs don't exist for these two actions.
  statement {
    sid       = "XRayWrite"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "webhook_receiver" {
  name   = "${local.lambda_function_names.webhook_receiver}-policy"
  role   = aws_iam_role.webhook_receiver.id
  policy = data.aws_iam_policy_document.webhook_receiver.json
}
