package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny Wildcard roles on BigQuery dataset IAM members (CR.SECURITY.034)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_dataset_iam_member"

	role := resource.change.after.role
	contains(role, "*")

	msg := sprintf("Security violation (CR.SECURITY.034): Wildcard role '%v' prohibited on BigQuery IAM binding: %v", [role, resource.address])
}
