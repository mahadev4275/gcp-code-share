package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny public access to storage bucket IAM member/binding
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"]
	
	member := get_member(resource.change.after)
	is_public_member(member)
	
	msg := sprintf("Security violation: Public member '%v' is not allowed on GCS bucket IAM: %v", [member, resource.address])
}

# 2. Deny public access to logging bucket view IAM member/binding
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["google_logging_project_bucket_iam_member", "google_logging_project_bucket_iam_binding"]
	
	member := get_member(resource.change.after)
	is_public_member(member)
	
	msg := sprintf("Security violation: Public member '%v' is not allowed on Logging Bucket IAM: %v", [member, resource.address])
}

# 3. Ensure Storage Public Access Prevention Org Policy is enforced
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_org_policy_policy"
	
	# Verify constraint name
	name := resource.change.after.name
	indexof(name, "storage.publicAccessPrevention") != -1
	
	# Check if not enforced
	not is_org_policy_enforced(resource.change.after)
	msg := sprintf("Security violation: Org policy '%v' is defined but not enforced", [resource.address])
}

# 4. If VPC-SC service perimeter is defined, make sure Cloud Logging is restricted
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_access_context_manager_service_perimeter"
	
	restricted_services := resource.change.after.status[0].restricted_services
	not "logging.googleapis.com" in restricted_services
	
	msg := sprintf("Security violation: VPC-SC perimeter '%v' does not restrict Cloud Logging (logging.googleapis.com)", [resource.address])
}

# Helpers
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

is_org_policy_enforced(after) if {
	after.spec[0].rules[0].enforce == true
}
