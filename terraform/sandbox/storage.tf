# Where runs exchange files (docs/sandbox-spec.md §6). A task never holds a
# credential for this bucket: sandbox-dispatch presigns one GET or PUT per
# object, and the S3 gateway endpoint's policy admits only runs/*.

resource "aws_s3_bucket" "sandbox" {
  bucket = "${local.name}-${data.aws_caller_identity.current.account_id}"
  # Dev, and everything in it is a run's scratch: destroy takes it.
  force_destroy = true
}

# The canary (leak test): a bucket the dispatch role can presign for, which
# the endpoint policy does not admit. A task given a valid URL for it must
# still fail, and only the endpoint policy can make that so.
resource "aws_s3_bucket" "canary" {
  bucket        = "${local.name}-canary-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "buckets" {
  for_each                = { sandbox = aws_s3_bucket.sandbox.id, canary = aws_s3_bucket.canary.id }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "buckets" {
  for_each = { sandbox = aws_s3_bucket.sandbox.id, canary = aws_s3_bucket.canary.id }
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# A run's files are read once, by collect, minutes after they are written.
resource "aws_s3_bucket_lifecycle_configuration" "sandbox" {
  bucket = aws_s3_bucket.sandbox.id
  rule {
    id     = "expire-runs"
    status = "Enabled"
    filter {}
    expiration {
      days = 2
    }
  }
}

data "aws_iam_policy_document" "tls_only" {
  for_each = { sandbox = aws_s3_bucket.sandbox.arn, canary = aws_s3_bucket.canary.arn }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value, "${each.value}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "buckets" {
  for_each = { sandbox = aws_s3_bucket.sandbox.id, canary = aws_s3_bucket.canary.id }
  bucket   = each.value
  policy   = data.aws_iam_policy_document.tls_only[each.key].json

  depends_on = [aws_s3_bucket_public_access_block.buckets]
}
