# Control effectiveness tests for the compliant-gcs module.
# Mocked provider: these verify the module's enforced configuration and its
# input validation, positive and negative, without cloud credentials.

mock_provider "google" {}

variables {
  gcp_project        = "example-project"
  project_label      = "cgep-lab"
  bucket_name_suffix = "test-001"
}

# Positive: a compliant dev request plans successfully AND the module has
# forced every control on, regardless of consumer input.
run "dev_baseline_enforces_controls" {
  command = plan

  variables {
    environment    = "dev"
    retention_days = 30
  }

  # AC-3: access enforcement
  assert {
    condition     = google_storage_bucket.bucket.uniform_bucket_level_access == true
    error_message = "AC-3: module must force uniform_bucket_level_access"
  }
  assert {
    condition     = google_storage_bucket.bucket.public_access_prevention == "enforced"
    error_message = "AC-3: module must force public_access_prevention = enforced"
  }

  # AU-11: audit record retention
  assert {
    condition     = google_storage_bucket.bucket.versioning[0].enabled == true
    error_message = "AU-11: module must force versioning"
  }
  assert {
    condition     = google_storage_bucket.bucket.retention_policy[0].retention_period == 2592000
    error_message = "AU-11: retention_period must equal retention_days * 86400"
  }

  # SC-12: key establishment (90-day rotation on the CMEK)
  assert {
    condition     = google_kms_crypto_key.key.rotation_period == "7776000s"
    error_message = "SC-12: CMEK rotation must be 90 days"
  }

  # CM-6: required labels present even when the consumer passes none
  assert {
    condition     = alltrue([for k in ["project", "environment", "managed_by", "compliance_scope"] : contains(keys(google_storage_bucket.bucket.labels), k)])
    error_message = "CM-6: all four compliance labels must be present"
  }
}

# CM-6 edge case: a consumer attempting to override a required label loses.
run "consumer_cannot_suppress_required_labels" {
  command = plan

  variables {
    environment    = "dev"
    retention_days = 30
    labels = {
      compliance_scope = "attacker-chosen"
      team             = "data"
    }
  }

  assert {
    condition     = google_storage_bucket.bucket.labels["compliance_scope"] == "cge-p-lab"
    error_message = "CM-6: required labels must win the merge over consumer labels"
  }
}

# Negative: prod with short retention must be rejected at plan time.
run "prod_short_retention_rejected_sc28_au11" {
  command = plan

  variables {
    environment    = "prod"
    retention_days = 30
  }

  expect_failures = [var.retention_days]
}

# Negative: an environment outside the allow-list is rejected (CM-6).
run "unknown_environment_rejected_cm6" {
  command = plan

  variables {
    environment    = "sandbox"
    retention_days = 30
  }

  expect_failures = [var.environment]
}
