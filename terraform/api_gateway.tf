# API Gateway fronting review-api (spec §4.1, §4.4 step 6).
#
# HTTP API rather than REST: the spec leaves the choice open, and nothing here
# needs REST's extra surface (request validators, usage plans, API keys).
#
# Every dashboard route requires a Cognito ID token, validated by API Gateway's
# native JWT authorizer before the Lambda is invoked (see cognito.tf for why
# this is in v1 rather than v1.1). The handler reads the caller's identity from
# the verified claims, so no route trusts a caller-supplied actor.
#
# The one exception is POST /github/webhook (lambda_webhook_receiver.tf), which
# GitHub calls and which is authenticated by HMAC signature instead.

resource "aws_apigatewayv2_api" "review" {
  name          = "${var.project}-${var.environment}-review-api"
  protocol_type = "HTTP"
  description   = "Review dashboard API: list findings, fetch diffs, record approve/reject decisions"

  cors_configuration {
    allow_origins = local.dashboard_origins
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["authorization", "content-type"]
    max_age       = 300
  }
}

resource "aws_cloudwatch_log_group" "review_api_gateway" {
  name              = "/aws/apigateway/${var.project}-${var.environment}-review-api"
  retention_in_days = 14
}

resource "aws_apigatewayv2_integration" "review_api" {
  api_id = aws_apigatewayv2_api.review.id

  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.review_api.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 12000
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.review.id
  name             = "${var.project}-${var.environment}-cognito"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    # Both clients: the dashboard's browser PKCE client and the CLI client used
    # to mint tokens for smoke tests. ID tokens carry aud = client_id, which is
    # why the dashboard sends the id_token rather than the access token -- and
    # why the access token, whose aud is absent, would be rejected here.
    audience = [
      aws_cognito_user_pool_client.dashboard.id,
      aws_cognito_user_pool_client.cli.id,
    ]
    issuer = "https://${aws_cognito_user_pool.dashboard.endpoint}"
  }
}

# One route per operation rather than a $default catch-all, so an unknown path
# is rejected at the gateway instead of inside the Lambda.
locals {
  review_api_routes = [
    "GET /prs/{pr_id}/findings",
    "GET /prs/{pr_id}/findings/{finding_id}",
    "GET /prs/{pr_id}/findings/{finding_id}/events",
    "GET /prs/{pr_id}/findings/{finding_id}/content",
    "POST /prs/{pr_id}/findings/{finding_id}/review",
  ]
}

resource "aws_apigatewayv2_route" "review_api" {
  for_each = toset(local.review_api_routes)

  api_id    = aws_apigatewayv2_api.review.id
  route_key = each.value
  target    = "integrations/${aws_apigatewayv2_integration.review_api.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_stage" "review" {
  api_id      = aws_apigatewayv2_api.review.id
  name        = "$default"
  auto_deploy = true

  # The unauthenticated route gets a throttle the JWT routes don't need: anyone
  # can POST to it, and every request costs a Lambda invocation and a Secrets
  # Manager read before the signature rejects it. GitHub's real rate for one
  # testbed repo is a few deliveries a minute.
  route_settings {
    route_key              = aws_apigatewayv2_route.github_webhook.route_key
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.review_api_gateway.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      httpMethod       = "$context.httpMethod"
      path             = "$context.path"
      routeKey         = "$context.routeKey"
      status           = "$context.status"
      responseLength   = "$context.responseLength"
      responseLatency  = "$context.responseLatency"
      integrationError = "$context.integrationErrorMessage"
      # Who the gateway authenticated, independent of anything the request body
      # claimed. Empty on a 401, which is how a rejected token is spotted here.
      sub = "$context.authorizer.claims.sub"
    })
  }
}

# Without this every call 500s -- the route target alone does not grant API
# Gateway permission to invoke the function.
resource "aws_lambda_permission" "review_api_gateway" {
  statement_id  = "AllowInvokeFromReviewApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.review_api.function_name
  principal     = "apigateway.amazonaws.com"

  # Scoped to this API; the trailing wildcard covers every stage/method/path.
  source_arn = "${aws_apigatewayv2_api.review.execution_arn}/*/*"
}

# Note on preflight: cors_configuration answers OPTIONS at the gateway before
# the authorizer runs, which is required -- a browser preflight carries no
# Authorization header and would otherwise get a 401 the browser reports as an
# opaque CORS failure.
