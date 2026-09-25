resource "aws_secretsmanager_secret" "anthropic_api_key" {
  name        = "${var.project}/${var.environment}/anthropic-api-key"
  description = "Anthropic API key used by mapping-agent and remediation-agent Lambdas"
}

# Placeholder value — set the real key out-of-band (console or `aws secretsmanager
# put-secret-value`) after apply. lifecycle.ignore_changes keeps subsequent applies
# from clobbering it and keeps the real key out of Terraform state/plan diffs.
resource "aws_secretsmanager_secret_version" "anthropic_api_key" {
  secret_id     = aws_secretsmanager_secret.anthropic_api_key.id
  secret_string = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ---------- GitHub App (v3, docs/ci-integration-spec.md §2.1, §4.1) ----------
#
# Unlike the Anthropic key above, these get NO placeholder version. The repo is
# public, so a webhook secret of "REPLACE_ME" would be a known HMAC key: anyone
# could sign a delivery that verifies. With no version at all, GetSecretValue
# fails and webhook-receiver rejects every request until the real value is set
# -- it fails closed instead of open. Set both out-of-band after apply:
#
#   aws secretsmanager put-secret-value --secret-id <webhook secret name> --secret-string <hex>
#   aws secretsmanager put-secret-value --secret-id <private key name> --secret-string file://<app>.pem
#
# Never through Terraform, so neither value is in state or a plan diff.

# Shared with GitHub; signs every delivery (X-Hub-Signature-256). Read only by
# webhook-receiver.
resource "aws_secretsmanager_secret" "github_webhook_secret" {
  name        = "${var.project}/${var.environment}/github-webhook-secret"
  description = "GitHub App webhook secret, used by webhook-receiver to verify delivery signatures"
}

# Signs the App's JWT, which mints installation tokens that can act on every
# repository the App is installed on. Read only by github-gateway (not yet
# built), never by anything API Gateway can reach.
resource "aws_secretsmanager_secret" "github_app_private_key" {
  name        = "${var.project}/${var.environment}/github-app-private-key"
  description = "GitHub App private key (PEM), used by github-gateway to mint installation tokens"
}
