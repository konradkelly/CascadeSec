# Roles for the v1 Lambdas (spec §4.1, §4.4). Function names are fixed here so
# permissions can be scoped ahead of the Lambda resources themselves, which are
# created in a later pass. webhook-receiver/SQS roles are deferred to v3 (GitHub
# CI integration) since v1 uses a manual trigger, not a webhook.
locals {
  lambda_function_names = {
    terraform_scanner = "${var.project}-${var.environment}-terraform-scanner"
    mapping_agent     = "${var.project}-${var.environment}-mapping-agent"
    remediation_agent = "${var.project}-${var.environment}-remediation-agent"
    review_api        = "${var.project}-${var.environment}-review-api"
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

# ---------- terraform-scanner ----------
# Runs Trivy + Checkov against snapshots in S3, writes raw findings to DynamoDB.

resource "aws_iam_role" "terraform_scanner" {
  name               = "${local.lambda_function_names.terraform_scanner}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "terraform_scanner" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_function_names.terraform_scanner}:*"]
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

resource "aws_iam_role_policy" "terraform_scanner" {
  name   = "${local.lambda_function_names.terraform_scanner}-policy"
  role   = aws_iam_role.terraform_scanner.id
  policy = data.aws_iam_policy_document.terraform_scanner.json
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
# Drafts a diff via Anthropic API, then invokes terraform-scanner to self-check it.

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
    sid       = "SelfCheckInvokeScanner"
    actions   = ["lambda:InvokeFunction"]
    resources = ["arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.lambda_function_names.terraform_scanner}"]
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
