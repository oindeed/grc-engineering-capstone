package terraform.gcs

import rego.v1

compliant_plan := {"resource_changes": [{
	"address": "module.data_bucket.google_storage_bucket.bucket",
	"type": "google_storage_bucket",
	"change": {
		"actions": ["create"],
		"after": {
			"uniform_bucket_level_access": true,
			"public_access_prevention": "enforced",
			"versioning": [{"enabled": true}],
			"retention_policy": [{"retention_period": 2592000}],
			"encryption": [{}],
			"labels": {
				"project": "cgep-lab",
				"environment": "dev",
				"managed_by": "terraform",
				"compliance_scope": "cge-p-lab",
			},
		},
		"after_unknown": {"encryption": [{"default_kms_key_name": true}]},
	},
}]}

test_compliant_plan_has_no_denies if {
	count(deny) == 0 with input as compliant_plan
}

test_ac3_public_access_denied if {
	bad := json.patch(compliant_plan, [{"op": "replace", "path": "/resource_changes/0/change/after/public_access_prevention", "value": "inherited"}])
	some msg in deny with input as bad
	contains(msg, "[AC-3]")
}

test_ac3_uniform_access_denied if {
	bad := json.patch(compliant_plan, [{"op": "replace", "path": "/resource_changes/0/change/after/uniform_bucket_level_access", "value": false}])
	some msg in deny with input as bad
	contains(msg, "[AC-3]")
}

test_au11_versioning_denied if {
	bad := json.patch(compliant_plan, [{"op": "replace", "path": "/resource_changes/0/change/after/versioning", "value": []}])
	some msg in deny with input as bad
	contains(msg, "[AU-11]")
}

test_sc28_prod_short_retention_denied if {
	bad := json.patch(compliant_plan, [{"op": "replace", "path": "/resource_changes/0/change/after/labels/environment", "value": "prod"}])
	some msg in deny with input as bad
	contains(msg, "[SC-28/AU-11]")
}

test_cmek_missing_denied if {
	bad := json.patch(compliant_plan, [
		{"op": "replace", "path": "/resource_changes/0/change/after/encryption", "value": []},
		{"op": "replace", "path": "/resource_changes/0/change/after_unknown", "value": {}},
	])
	some msg in deny with input as bad
	contains(msg, "[SC-12/SC-13/SC-28]")
}

test_cm6_missing_label_denied if {
	bad := json.patch(compliant_plan, [{"op": "remove", "path": "/resource_changes/0/change/after/labels/compliance_scope"}])
	some msg in deny with input as bad
	contains(msg, "[CM-6]")
}

test_delete_actions_are_out_of_scope if {
	del := json.patch(compliant_plan, [
		{"op": "replace", "path": "/resource_changes/0/change/actions", "value": ["delete"]},
		{"op": "replace", "path": "/resource_changes/0/change/after", "value": null},
	])
	count(deny) == 0 with input as del
}
