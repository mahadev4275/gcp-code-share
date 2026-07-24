package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Warn if Logging Buckets do not specify cmek_settings (CR.SECURITY.009)
warn contains msg if {
	some resource in input.resource_changes
	resource.type == "google_logging_project_bucket_config"

	cmek := object.get(resource.change.after, "cmek_settings", [])
	not is_cmek_configured(cmek)

	msg := sprintf("Security warning (CR.SECURITY.009): Logging bucket '%v' missing cmek_settings.kms_key_name", [resource.address])
}

# 2. Deny Public Members on Logging Bucket IAM (CR.SECURITY.037)
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["google_logging_project_bucket_iam_member", "google_logging_project_bucket_iam_binding"]

	member := get_member(resource.change.after)
	is_public_member(member)

	msg := sprintf("Security violation (CR.SECURITY.037): Public member '%v' is prohibited on logging bucket IAM: %v", [member, resource.address])
}

is_cmek_configured(cmek) if {
	is_array(cmek)
	count(cmek) > 0
	cmek[0].kms_key_name != ""
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
