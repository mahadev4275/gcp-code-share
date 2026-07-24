package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny public access on BigQuery Dataset IAM Members (CR.SECURITY.037)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_dataset_iam_member"

	member := resource.change.after.member
	is_public_member(member)

	msg := sprintf("Security violation (CR.SECURITY.037): Public member '%v' is not allowed on BigQuery dataset IAM: %v", [member, resource.address])
}

# 2. Deny wildcard roles/permissions (CR.SECURITY.034)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_dataset_iam_member"

	role := resource.change.after.role
	contains(role, "*")

	msg := sprintf("Security violation (CR.SECURITY.034): Wildcard role '%v' is prohibited on BigQuery dataset IAM: %v", [role, resource.address])
}

is_public_member(member) if {
	member == "allUsers"
}
is_public_member(member) if {
	member == "allAuthenticatedUsers"
}
