# sandbox-dispatch (docs/sandbox-spec.md §6): the trusted side of a run.
# prepare presigns and fetches the CodeArtifact token, reap stops what
# outlived its run, collect reads what the task wrote as hostile input.
#
# Its permissions travel: a presigned URL acts with this role's rights for
# its one object, and a CodeArtifact token with this role's CodeArtifact
# rights for fifteen minutes. So the role may read the mirrors and must
# never be able to publish to them.

data "archive_file" "dispatch" {
  type        = "zip"
  output_path = "${path.module}/../../lambda/sandbox-dispatch/handler.zip"

  source {
    content  = file("${path.module}/../../lambda/sandbox-dispatch/handler.py")
    filename = "handler.py"
  }
  source {
    content  = file("${path.module}/../../lambda/sandbox-dispatch/leak.py")
    filename = "leak.py"
  }
}

resource "aws_cloudwatch_log_group" "dispatch" {
  name              = "/aws/lambda/${local.name}-dispatch"
  retention_in_days = 14
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dispatch" {
  name               = "${local.name}-dispatch"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "dispatch" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.dispatch.arn}:*"]
  }
  statement {
    # Presigning for the task, and collect's own reads.
    sid       = "Runs"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.sandbox.arn}/runs/*"]
  }
  statement {
    # So a missing result.json is a 404 rather than a 403.
    sid       = "ListRuns"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.sandbox.arn]
  }
  statement {
    # The canary URL has to be valid for the leak test to mean anything:
    # if it failed because this role could not write there, the endpoint
    # policy would be untested.
    sid       = "Canary"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.canary.arn}/*"]
  }
  statement {
    sid       = "CodeArtifactToken"
    actions   = ["codeartifact:GetAuthorizationToken"]
    resources = [aws_codeartifact_domain.sandbox.arn]
  }
  statement {
    sid       = "CodeArtifactBearer"
    actions   = ["sts:GetServiceBearerToken"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "sts:AWSServiceName"
      values   = ["codeartifact.amazonaws.com"]
    }
  }
  statement {
    # Read, and nothing else: the token handed to the fetch task carries
    # exactly these rights.
    sid     = "CodeArtifactRead"
    actions = ["codeartifact:GetRepositoryEndpoint", "codeartifact:ReadFromRepository"]
    resources = [
      aws_codeartifact_repository.npm.arn,
      aws_codeartifact_repository.pypi.arn,
    ]
  }
  statement {
    sid       = "ReapList"
    actions   = ["ecs:ListTasks"]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.sandbox.arn]
    }
  }
  statement {
    sid       = "ReapStop"
    actions   = ["ecs:StopTask", "ecs:DescribeTasks"]
    resources = ["arn:aws:ecs:${local.region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.sandbox.name}/*"]
  }
}

resource "aws_iam_role_policy" "dispatch" {
  role   = aws_iam_role.dispatch.id
  policy = data.aws_iam_policy_document.dispatch.json
}

resource "aws_lambda_function" "dispatch" {
  function_name = "${local.name}-dispatch"
  role          = aws_iam_role.dispatch.arn

  filename         = data.archive_file.dispatch.output_path
  source_code_hash = data.archive_file.dispatch.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  timeout     = 30
  memory_size = 256

  environment {
    variables = {
      SANDBOX_BUCKET        = aws_s3_bucket.sandbox.bucket
      CANARY_BUCKET         = aws_s3_bucket.canary.bucket
      CLUSTER_ARN           = aws_ecs_cluster.sandbox.arn
      CODEARTIFACT_DOMAIN   = aws_codeartifact_domain.sandbox.domain
      CODEARTIFACT_OWNER    = data.aws_caller_identity.current.account_id
      CODEARTIFACT_NPM_REPO = aws_codeartifact_repository.npm.repository
      ECR_REGISTRY          = split("/", aws_ecr_repository.node22.repository_url)[0]
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.dispatch,
    aws_iam_role_policy.dispatch,
  ]
}
