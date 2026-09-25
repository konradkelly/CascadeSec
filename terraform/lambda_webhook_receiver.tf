# webhook-receiver Lambda and its route (docs/ci-integration-spec.md §3).
# No layers -- it needs hmac, json and boto3, all in the runtime.
#
# The route shares the review API rather than getting its own: same gateway,
# same access log, one more route. What differs is the auth -- see the route
# below.

data "archive_file" "webhook_receiver_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/webhook-receiver/handler.py"
  output_path = "${path.module}/../lambda/webhook-receiver/handler.zip"
}

resource "aws_cloudwatch_log_group" "webhook_receiver" {
  name              = "/aws/lambda/${local.lambda_function_names.webhook_receiver}"
  retention_in_days = 14
}

resource "aws_lambda_function" "webhook_receiver" {
  function_name = local.lambda_function_names.webhook_receiver
  role          = aws_iam_role.webhook_receiver.arn

  filename         = data.archive_file.webhook_receiver_handler.output_path
  source_code_hash = data.archive_file.webhook_receiver_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  # The start of the trace spec §4.1 wants: delivery -> execution -> each stage.
  tracing_config {
    mode = "Active"
  }

  # GitHub gives a delivery 10 seconds before marking it failed. The work is
  # one secret read and one StartExecution, so 8s is generous and still
  # leaves the gateway room to return the function's answer inside GitHub's
  # window rather than its own timeout.
  timeout     = 8
  memory_size = 256

  environment {
    variables = {
      WEBHOOK_SECRET_ARN = aws_secretsmanager_secret.github_webhook_secret.arn
      STATE_MACHINE_ARN  = aws_sfn_state_machine.pipeline.arn
      # Dimension on the metrics the handler emits (observability.tf).
      ENVIRONMENT = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.webhook_receiver,
    aws_iam_role_policy.webhook_receiver,
  ]
}

resource "aws_apigatewayv2_integration" "webhook_receiver" {
  api_id = aws_apigatewayv2_api.review.id

  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.webhook_receiver.invoke_arn
  payload_format_version = "2.0"
  # Just past the function's own 8s, and inside GitHub's 10s.
  timeout_milliseconds = 9000
}

# The one route with no JWT authorizer, deliberately: GitHub cannot present a
# Cognito token. Its auth is the X-Hub-Signature-256 HMAC, checked inside the
# function against the raw body before anything is parsed -- which is why this
# route must never be pointed at any other integration.
resource "aws_apigatewayv2_route" "github_webhook" {
  api_id    = aws_apigatewayv2_api.review.id
  route_key = "POST /github/webhook"
  target    = "integrations/${aws_apigatewayv2_integration.webhook_receiver.id}"

  authorization_type = "NONE"
}

resource "aws_lambda_permission" "webhook_receiver_gateway" {
  statement_id  = "AllowInvokeFromReviewApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.webhook_receiver.function_name
  principal     = "apigateway.amazonaws.com"

  # This route only, unlike review-api's wildcard: nothing else on the API
  # should be able to reach this function.
  source_arn = "${aws_apigatewayv2_api.review.execution_arn}/*/POST/github/webhook"
}
