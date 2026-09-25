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
# Unlike the Anthropic key above, this gets NO placeholder version. The repo is
# public, so a webhook secret of "REPLACE_ME" would be a known HMAC key: anyone
# could sign a delivery that verifies. With no version at all, GetSecretValue
# fails and webhook-receiver rejects every request until the real value is set
# -- it fails closed instead of open. Set it out-of-band after apply:
#
#   aws secretsmanager put-secret-value --secret-id <webhook secret name> --secret-string <hex>
#
# Never through Terraform, so the value is in neither state nor a plan diff.

# Shared with GitHub; signs every delivery (X-Hub-Signature-256). Read only by
# webhook-receiver.
resource "aws_secretsmanager_secret" "github_webhook_secret" {
  name        = "${var.project}/${var.environment}/github-webhook-secret"
  description = "GitHub App webhook secret, used by webhook-receiver to verify delivery signatures"
}

# The App's private key is not here. It was, briefly (2026-09-24), before it
# moved to KMS, where github-gateway can sign with it but nothing can read it
# (lambda_github_gateway.tf, docs/ci-integration-spec.md §4.1). Removing the
# resource schedules the old secret for deletion with Secrets Manager's
# default 30-day recovery window, during which it cannot be read either.
