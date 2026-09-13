output "artifacts_bucket_name" {
  value = aws_s3_bucket.artifacts.bucket
}

output "findings_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "findings_table_arn" {
  value = aws_dynamodb_table.findings.arn
}

output "anthropic_api_key_secret_arn" {
  value = aws_secretsmanager_secret.anthropic_api_key.arn
}

output "lambda_role_arns" {
  value = {
    terraform_scanner = aws_iam_role.terraform_scanner.arn
    mapping_agent     = aws_iam_role.mapping_agent.arn
    remediation_agent = aws_iam_role.remediation_agent.arn
    context_agent     = aws_iam_role.context_agent.arn
    review_api        = aws_iam_role.review_api.arn
  }
}

output "terraform_scanner_function_name" {
  value = aws_lambda_function.terraform_scanner.function_name
}

output "terraform_scanner_function_arn" {
  value = aws_lambda_function.terraform_scanner.arn
}

output "mapping_agent_function_name" {
  value = aws_lambda_function.mapping_agent.function_name
}

output "mapping_agent_function_arn" {
  value = aws_lambda_function.mapping_agent.arn
}

output "remediation_agent_function_name" {
  value = aws_lambda_function.remediation_agent.function_name
}

output "remediation_agent_function_arn" {
  value = aws_lambda_function.remediation_agent.arn
}

output "context_agent_function_name" {
  value = aws_lambda_function.context_agent.function_name
}

output "review_api_function_name" {
  value = aws_lambda_function.review_api.function_name
}

# Base URL the dashboard talks to, e.g.
#   curl "$(terraform output -raw review_api_endpoint)/prs/manual-1/findings"
output "review_api_endpoint" {
  value = aws_apigatewayv2_stage.review.invoke_url
}

output "dashboard_bucket_name" {
  value = aws_s3_bucket.dashboard.bucket
}

# Deploy the built dashboard:
#   aws s3 sync dashboard/dist/ "s3://$(terraform output -raw dashboard_bucket_name)/" --delete
#   aws cloudfront create-invalidation --distribution-id "$(terraform output -raw dashboard_distribution_id)" --paths '/*'
output "dashboard_distribution_id" {
  value = aws_cloudfront_distribution.dashboard.id
}

output "dashboard_url" {
  value = "https://${aws_cloudfront_distribution.dashboard.domain_name}"
}

# Dashboard build-time config -- copy these into dashboard/.env:
#   VITE_COGNITO_DOMAIN, VITE_COGNITO_CLIENT_ID
output "cognito_hosted_ui_domain" {
  value = "${aws_cognito_user_pool_domain.dashboard.domain}.auth.${var.aws_region}.amazoncognito.com"
}

output "cognito_dashboard_client_id" {
  value = aws_cognito_user_pool_client.dashboard.id
}

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.dashboard.id
}

# Used only by smoke tests that mint a token without a browser:
#   aws cognito-idp admin-initiate-auth --auth-flow ADMIN_USER_PASSWORD_AUTH #     --user-pool-id "$(terraform output -raw cognito_user_pool_id)" #     --client-id "$(terraform output -raw cognito_cli_client_id)" #     --auth-parameters "USERNAME=$EMAIL,PASSWORD=$PASSWORD"
output "cognito_cli_client_id" {
  value = aws_cognito_user_pool_client.cli.id
}
