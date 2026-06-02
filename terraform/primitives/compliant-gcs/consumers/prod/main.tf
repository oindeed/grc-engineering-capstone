# consumers/prod/main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = "project-234b8605-959f-41d3-8fd"
  region  = "us-central1"
}

module "data_bucket" {
  source = "../.."

  gcp_project        = "project-234b8605-959f-41d3-8fd"
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 365
  bucket_name_suffix = "prod-data-001"
}

output "attestation" { value = module.data_bucket.compliance_attestation }
output "bucket_url"  { value = module.data_bucket.bucket_url }
