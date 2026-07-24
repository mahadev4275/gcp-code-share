package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny Logging Buckets that do not specify cmek_settings (CR.SECURITY.009)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_logging_project_bucket_config"

	cmek := object.get(resource.change.after, "cmek_settings", [])
	not is_cmek_configured(cmek)

	msg := sprintf("Security violation (CR.SECURITY.009): Logging bucket '%v' missing cmek_settings block", [resource.address])
}

# 2. Deny KMS Crypto Keys without rotation_period (CR.SECURITY.009)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_kms_crypto_key"

	rotation := resource.change.after.rotation_period
	not rotation

	msg := sprintf("Security violation (CR.SECURITY.009): KMS Crypto Key '%v' missing rotation_period", [resource.address])
}

# 3. Deny Wildcard permissions on KMS Key IAM (CR.SECURITY.034)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_kms_crypto_key_iam_member"

	role := resource.change.after.role
	contains(role, "*")

	msg := sprintf("Security violation (CR.SECURITY.034): Wildcard role '%v' prohibited on KMS IAM: %v", [role, resource.address])
}

is_cmek_configured(cmek) if {
	is_array(cmek)
	count(cmek) > 0
}
