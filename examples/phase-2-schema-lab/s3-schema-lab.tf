
# NET-004 S3 schema inspection fixtures.
# These resources are for Terraform plan inspection only.
# They must never be applied to AWS.

resource "aws_s3_bucket" "net004_acl" {
  bucket = "policy-engine-net004-acl-schema-lab"
}

resource "aws_s3_bucket_acl" "net004_acl" {
  bucket = "policy-engine-net004-acl-schema-lab"

  access_control_policy {
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/global/AllUsers"
      }

      permission = "READ"
    }

    owner {
      id = "00000000000000000000000000000000"
    }
  }
}

resource "aws_s3_bucket" "net004_policy" {
  bucket = "policy-engine-net004-policy-schema-lab"
}

resource "aws_s3_bucket_policy" "net004_policy" {
  bucket = "policy-engine-net004-policy-schema-lab"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "arn:aws:s3:::policy-engine-net004-policy-schema-lab/*"
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "net004_acl" {
  bucket = "policy-engine-net004-acl-schema-lab"

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_public_access_block" "net004_policy" {
  bucket = "policy-engine-net004-acl-schema-lab"

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_account_public_access_block" "net004" {
  account_id = "123456789012"

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}
