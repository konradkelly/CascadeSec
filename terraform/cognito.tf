# Cognito user pool + Hosted UI for the review dashboard (spec §4.1, §8).
#
# The spec lists Cognito as an optional v1.1 item. Pulled into v1 because the
# API it fronts serves a list of unfixed vulnerabilities with their file paths,
# and its review route marks findings resolved. Throttling is not a substitute
# for either half: one unauthenticated request is enough to resolve a real
# finding, and an audit trail whose actor is a self-asserted string records
# claims rather than facts. The JWT's identity is what makes it evidence.

locals {
  # The exact origins the dashboard is served from. Both the CORS allow-list
  # and Cognito's callback/logout URLs derive from this list, so the two can't
  # drift. Cognito matches redirect_uri verbatim -- a mismatch shows up as a
  # Hosted UI error page, not a silent fallback.
  dashboard_origins = concat(
    ["https://${aws_cloudfront_distribution.dashboard.domain_name}"],
    var.dashboard_extra_origins,
  )
}

resource "aws_cognito_user_pool" "dashboard" {
  name                     = "${var.project}-${var.environment}-dashboard"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # The most important setting in this file. Without it the Hosted UI offers
  # self-registration, and anyone who reaches the URL can sign themselves up
  # and read every finding.
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
}

# Hosted UI domain prefixes are unique per region, so this carries the account
# id -- same approach as the bucket names in s3.tf and cloudfront_dashboard.tf.
resource "aws_cognito_user_pool_domain" "dashboard" {
  domain       = "${var.project}-${var.environment}-${data.aws_caller_identity.current.account_id}"
  user_pool_id = aws_cognito_user_pool.dashboard.id
}

resource "aws_cognito_user_pool_client" "dashboard" {
  name         = "${var.project}-${var.environment}-dashboard"
  user_pool_id = aws_cognito_user_pool.dashboard.id

  # Public SPA client: no secret survives in a browser bundle, and omitting one
  # is what makes Cognito require PKCE (S256) on the code flow -- there is no
  # separate flag for that.
  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]

  callback_urls = [for origin in local.dashboard_origins : "${origin}/auth/callback"]
  logout_urls   = local.dashboard_origins

  # No SRP or password auth from the browser: the Hosted UI is the only way in.
  explicit_auth_flows           = ["ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors = "ENABLED"

  id_token_validity      = 60
  access_token_validity  = 60
  refresh_token_validity = 1

  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "days"
  }
}

# Test-only client with no browser flow, so `aws cognito-idp
# admin-initiate-auth` can mint an id_token and the API stays curl-scriptable
# without a browser round trip. See dashboard/README.md.
resource "aws_cognito_user_pool_client" "cli" {
  name         = "${var.project}-${var.environment}-cli"
  user_pool_id = aws_cognito_user_pool.dashboard.id

  generate_secret     = false
  explicit_auth_flows = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
}

# Who may commit approved fixes to a branch (write-back-spec §9, W6).
# Approving stays open to every reviewer; a commit is a write to someone's
# repository, so review-api refuses POST /prs/{pr_id}/commits unless the
# verified ID token's cognito:groups carries this. Membership is out of band,
# like the accounts themselves:
#
#   aws cognito-idp admin-add-user-to-group --user-pool-id <pool> #     --username <email> --group-name committers
#
# A group claim is issued at sign-in, so a new member signs in again.
resource "aws_cognito_user_group" "committers" {
  name         = "committers"
  user_pool_id = aws_cognito_user_pool.dashboard.id
  description  = "May commit approved fixes to a pull request's branch"
}

# Reviewer accounts are created out of band with `aws cognito-idp
# admin-create-user` (documented in dashboard/README.md). Deliberately not an
# aws_cognito_user resource: a human's account doesn't belong in config, and
# the temporary password would land in state.
