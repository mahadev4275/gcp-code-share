package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny Wildcard Permissions in IAM bindings for Scheduled Query SA (CR.SECURITY.034)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_dataset_iam_member"

	role := resource.change.after.role
	contains(role, "*")

	msg := sprintf("Security violation (CR.SECURITY.034): Wildcard role '%v' is prohibited on scheduled query IAM binding: %v", [role, resource.address])
}

# 2. Deny Public Access on Scheduled Query SA or IAM bindings (CR.SECURITY.037)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_dataset_iam_member"

	member := resource.change.after.member
	is_public_member(member)

	msg := sprintf("Security violation (CR.SECURITY.037): Public member '%v' is prohibited: %v", [member, resource.address])
}

is_public_member(member) if {
	member == "allUsers"
}
is_public_member(member) if {
	member == "allAuthenticatedUsers"
}
