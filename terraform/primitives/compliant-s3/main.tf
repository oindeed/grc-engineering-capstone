# main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = var.environment
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  effective_suffix = var.bucket_suffix != "" ? var.bucket_suffix : random_id.bucket_suffix.hex
  primary_name     = "${var.project_name}-${var.environment}-data-${local.effective_suffix}"
  log_name         = "${var.project_name}-${var.environment}-logs-${local.effective_suffix}"
}

resource "aws_s3_bucket" "primary" {
  #checkov:skip=CKV_AWS_144: Cross-region replication is a resilience control, not a confidentiality or integrity control, and is out of scope for a single-region lab primitive.
  #checkov:skip=CKV2_AWS_61: Lifecycle configuration is out of scope; this primitive demonstrates encryption, access enforcement, and versioning, not data lifecycle management.
  #checkov:skip=CKV2_AWS_62: Event notifications are out of scope; this primitive has no downstream consumer to notify.
  #checkov:skip=CKV_AWS_145: This primitive uses SSE-S3 (AES256) by design as the Lab 2.3 baseline. Customer-managed key encryption (SC-12/SC-13) is demonstrated end to end in the compliant-gcs chain, which is the capstone scope. See README Scope.
  bucket = local.primary_name
}

# SC-28: Protection of information at rest.
# AES-256 keeps this lab simple. The commented block below shows how you'd
# switch to KMS-managed keys, covered in a later lab.
resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }

  # KMS teaser:
  # rule {
  #   apply_server_side_encryption_by_default {
  #     sse_algorithm     = "aws:kms"
  #     kms_master_key_id = aws_kms_key.bucket.arn
  #   }
  #   bucket_key_enabled = true
  # }
}

# CM-6: Versioning preserves prior object states for recovery and audit.
resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
}

# AC-3: Access control, explicit deny on every public access vector.
resource "aws_s3_bucket_public_access_block" "primary" {
  bucket                  = aws_s3_bucket.primary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AU-3 / AU-6: Content of audit records + audit review.
resource "aws_s3_bucket" "log" {
  #checkov:skip=CKV_AWS_144: Cross-region replication is out of scope for a single-region lab primitive.
  #checkov:skip=CKV2_AWS_61: Lifecycle configuration is out of scope for this primitive.
  #checkov:skip=CKV2_AWS_62: Event notifications are out of scope; nothing consumes these logs downstream in the lab.
  #checkov:skip=CKV_AWS_145: SSE-S3 (AES256) by design, consistent with the primary bucket. CMEK is demonstrated in the compliant-gcs chain.
  bucket = local.log_name
}

resource "aws_s3_bucket_ownership_controls" "log" {
  #checkov:skip=CKV2_AWS_65: BucketOwnerEnforced would disable ACLs entirely, which breaks the log-delivery-write ACL that S3 log delivery depends on (see aws_s3_bucket_acl.log). Migrating to bucket-policy-based log delivery is the correct modern fix and is out of scope for this primitive.
  bucket = aws_s3_bucket.log.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "log" {
  depends_on = [aws_s3_bucket_ownership_controls.log]
  bucket     = aws_s3_bucket.log.id
  acl        = "log-delivery-write"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "log" {
  bucket                  = aws_s3_bucket.log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "primary" {
  bucket        = aws_s3_bucket.primary.id
  target_bucket = aws_s3_bucket.log.id
  target_prefix = "access-logs/"
}

# AU-11: Audit record retention. Versioning on the log bucket preserves prior
# generations of delivered access logs against overwrite or deletion.
resource "aws_s3_bucket_versioning" "log" {
  bucket = aws_s3_bucket.log.id
  versioning_configuration {
    status = "Enabled"
  }
}
