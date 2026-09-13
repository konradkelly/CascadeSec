resource "aws_s3_bucket" "data" {
  bucket = "iacposture-fixture-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/iacposture-fixture-data"
    }
  }
}
