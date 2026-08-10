package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny if Logging Buckets do not specify cmek_settings (CR.SECURITY.009)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_logging_project_bucket_config"

	cmek_after := object.get(resource.change.after, "cmek_settings", [])
	cmek_unknown := object.get(object.get(resource.change, "after_unknown", {}), "cmek_settings", [])
	not is_cmek_configured(cmek_after, cmek_unknown)

	msg := sprintf("Security violation (CR.SECURITY.009): Logging bucket '%v' missing cmek_settings.kms_key_name", [resource.address])
}

# 2. Deny Public Members on Logging Bucket IAM (CR.SECURITY.037)
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["google_logging_project_bucket_iam_member", "google_logging_project_bucket_iam_binding"]

	member := get_member(resource.change.after)
	is_public_member(member)

	msg := sprintf("Security violation (CR.SECURITY.037): Public member '%v' is prohibited on logging bucket IAM: %v", [member, resource.address])
}

# CMEK is configured if kms_key_name is explicitly set in 'after'
is_cmek_configured(cmek_after, _) if {
	is_array(cmek_after)
	count(cmek_after) > 0
	cmek_after[0].kms_key_name != ""
}

# CMEK is also configured if kms_key_name is "known after apply" (appears in after_unknown)
is_cmek_configured(cmek_after, cmek_unknown) if {
	is_array(cmek_after)
	count(cmek_after) > 0
	is_array(cmek_unknown)
	count(cmek_unknown) > 0
	cmek_unknown[0].kms_key_name == true
}

is_public_member(member) if {
	member == "allUsers"
}
is_public_member(member) if {
	member == "allAuthenticatedUsers"
}

get_member(after) = member if {
	member := after.member
}
get_member(after) = member if {
	member := after.members[_]
}
