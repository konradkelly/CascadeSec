# Single bucket, three prefixes:
#   scans/  - raw Terraform snapshots per scan run (transient, expired below)
#   fixes/  - each fix's corrected file: the agent's draft, overwritten by a
#             reviewer's edit. Read back as the base for every fix drafted on
#             top of it, so it must outlive the snapshot -- an S3 lifecycle
#             rule cannot exempt a sub-prefix, which is why this is not under
#             scans/. See docs/reviewer-edit-spec.md §2.2.
#   corpus/ - versioned CIS/OWASP control text (long-lived, relies on bucket versioning)
resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.project}-${var.environment}-artifacts-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# scans/ are per-run artifacts, not meant to be retained indefinitely
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  # A project tarball is read once, by the sandbox run that follows it
  # within minutes (docs/sandbox-spec.md §9 step 2). It holds a whole
  # repository, so it is kept no longer than that needs.
  rule {
    id     = "expire-cdk-projects"
    status = "Enabled"

    filter {
      prefix = "projects/"
    }

    expiration {
      days = 2
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  rule {
    id     = "expire-old-scan-snapshots"
    status = "Enabled"

    filter {
      prefix = "scans/"
    }

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}
