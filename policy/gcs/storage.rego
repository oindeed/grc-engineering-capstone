# Merge-time policy gate for the compliant-gcs primitive.
# Input: terraform show -json plan output.
# These rules re-assert, at plan review time, the same NIST 800-53 rev 5
# controls the module hardcodes at build time. A plan that cannot satisfy
# them is denied before merge. Scope: google_storage_bucket only.
package terraform.gcs

import rego.v1

# Buckets being created or updated in this plan (deletes are out of scope).
buckets contains rc if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	some action in rc.change.actions
	action in {"create", "update"}
}

# AC-3 (access enforcement): uniform bucket-level access must be on.
deny contains msg if {
	some rc in buckets
	not rc.change.after.uniform_bucket_level_access == true
	msg := sprintf("[AC-3] %s: uniform_bucket_level_access must be true", [rc.address])
}

# AC-3 (access enforcement): public access prevention must be enforced.
deny contains msg if {
	some rc in buckets
	rc.change.after.public_access_prevention != "enforced"
	msg := sprintf("[AC-3] %s: public_access_prevention must be \"enforced\"", [rc.address])
}

# AU-11 (audit record retention): object versioning must be enabled.
deny contains msg if {
	some rc in buckets
	not versioning_enabled(rc)
	msg := sprintf("[AU-11] %s: versioning must be enabled", [rc.address])
}

versioning_enabled(rc) if rc.change.after.versioning[0].enabled == true

# AU-11: a retention policy must exist.
deny contains msg if {
	some rc in buckets
	not has_retention(rc)
	msg := sprintf("[AU-11] %s: retention_policy must be set", [rc.address])
}

has_retention(rc) if rc.change.after.retention_policy[0].retention_period > 0

# SC-28 + AU-11 cross-check: prod-labeled buckets need >= 365d retention.
# Mirrors the module's variable validation as a second, independent gate.
deny contains msg if {
	some rc in buckets
	rc.change.after.labels.environment == "prod"
	rc.change.after.retention_policy[0].retention_period < 31536000
	msg := sprintf("[SC-28/AU-11] %s: prod buckets require retention >= 365 days", [rc.address])
}

# SC-12 / SC-13 / SC-28: CMEK required. The key name is usually unknown at
# plan time (computed from the key resource), so accept either a concrete
# encryption block or one marked unknown-after-apply. Absence of both means
# no CMEK was configured.
deny contains msg if {
	some rc in buckets
	not has_cmek(rc)
	msg := sprintf("[SC-12/SC-13/SC-28] %s: CMEK encryption block is required", [rc.address])
}

has_cmek(rc) if count(rc.change.after.encryption) > 0

has_cmek(rc) if rc.change.after_unknown.encryption[0].default_kms_key_name == true

# CM-6 (configuration settings): the four compliance labels must be present.
required_labels := {"project", "environment", "managed_by", "compliance_scope"}

deny contains msg if {
	some rc in buckets
	some label in required_labels
	not rc.change.after.labels[label]
	msg := sprintf("[CM-6] %s: required label %q is missing", [rc.address, label])
}
