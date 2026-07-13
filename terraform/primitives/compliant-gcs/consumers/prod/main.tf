terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

variable "gcp_project" {
  type        = string
  description = "GCP project ID to deploy into. Supplied via terraform.tfvars (not committed) or TF_VAR_gcp_project."
}

provider "google" {
  project = var.gcp_project
  region  = "us-central1"
}

module "data_bucket" {
  source = "../.."

  gcp_project        = var.gcp_project
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 365
  bucket_name_suffix = "prod-data-001"
}

output "attestation" { value = module.data_bucket.compliance_attestation }
output "bucket_url" { value = module.data_bucket.bucket_url }
