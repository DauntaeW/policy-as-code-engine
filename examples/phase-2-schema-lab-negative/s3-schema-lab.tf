
# AWS-NET-004 compliant S3 integration fixture.
# Terraform plan evaluation only. Never apply.

resource "aws_s3_bucket" "net004_acl" {
  bucket = "policy-engine-net004-acl-negative"
}

resource "aws_s3_bucket_acl" "net004_acl" {
  bucket = aws_s3_bucket.net004_acl.id
  acl    = "private"
}

resource "aws_s3_bucket" "net004_policy" {
  bucket = "policy-engine-net004-policy-negative"
}

resource "aws_s3_bucket_policy" "net004_policy" {
  bucket = aws_s3_bucket.net004_policy.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }

        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::policy-engine-net004-policy-negative/*"
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "net004_acl" {
  bucket = aws_s3_bucket.net004_acl.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "net004_policy" {
  bucket = aws_s3_bucket.net004_policy.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_account_public_access_block" "net004" {
  account_id = "123456789012"

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
