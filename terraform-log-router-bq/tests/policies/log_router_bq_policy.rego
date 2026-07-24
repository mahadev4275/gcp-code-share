package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny if BigQuery Dataset for Log Router missing CMEK (CR.SECURITY.009)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_dataset"

	enc := object.get(resource.change.after, "default_encryption_configuration", [])
	not is_bq_cmek_configured(enc)

	msg := sprintf("Security violation (CR.SECURITY.009): BigQuery dataset '%v' missing default_encryption_configuration.kms_key_name", [resource.address])
}

# 2. Deny Wildcard roles on BigQuery dataset IAM members (CR.SECURITY.034)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_dataset_iam_member"

	role := resource.change.after.role
	contains(role, "*")

	msg := sprintf("Security violation (CR.SECURITY.034): Wildcard role '%v' prohibited on BigQuery IAM binding: %v", [role, resource.address])
}

is_bq_cmek_configured(enc) if {
	is_array(enc)
	count(enc) > 0
	enc[0].kms_key_name != ""
}
