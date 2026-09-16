# Static hosting for the review dashboard (spec §4.1 "CloudFront + S3").
#
# The bucket is PRIVATE and stays that way. CloudFront reads it through an
# Origin Access Control, which signs each origin request with an identity the
# bucket policy trusts; nobody else can read the bucket at all.
#
# The older way to do this is a public bucket serving the S3 website endpoint.
# Don't. It would trip aws-s3-block-public-acls / aws-s3-block-public-policy,
# which this project's own corpus maps to CIS-AWS 2.1.5 -- iac-scanner
# would flag our own infrastructure. It also lets people bypass CloudFront by
# hitting the bucket URL directly, and the S3 website endpoint can't do HTTPS.

resource "aws_s3_bucket" "dashboard" {
  bucket = "${var.project}-${var.environment}-dashboard-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_cloudfront_origin_access_control" "dashboard" {
  name                              = "${var.project}-${var.environment}-dashboard-oac"
  description                       = "Lets the dashboard distribution read the private dashboard bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "dashboard" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "${var.project}-${var.environment} review dashboard"
  price_class         = "PriceClass_100"

  origin {
    # Regional REST endpoint, not the website endpoint -- OAC only works here.
    domain_name              = aws_s3_bucket.dashboard.bucket_regional_domain_name
    origin_id                = "dashboard-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.dashboard.id
  }

  default_cache_behavior {
    target_origin_id       = "dashboard-s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    # AWS managed policy "CachingOptimized".
    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  }

  # The dashboard is a single-page app: react-router owns paths like
  # /prs/{id}/findings, which don't exist as S3 objects. Without this, opening
  # or refreshing one of those URLs returns S3's 403/404 instead of the app.
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# Grants read to this distribution only -- the SourceArn condition is what
# stops any other CloudFront distribution from using the same OAC to read it.
data "aws_iam_policy_document" "dashboard_bucket" {
  statement {
    sid       = "AllowCloudFrontRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.dashboard.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.dashboard.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id
  policy = data.aws_iam_policy_document.dashboard_bucket.json

  # The public access block must exist first, or the bucket is briefly
  # policy-writable while unblocked.
  depends_on = [aws_s3_bucket_public_access_block.dashboard]
}
