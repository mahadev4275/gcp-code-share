package iam_wildcards

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# Deny wildcard permissions in IAM bindings and custom role definitions (unless in explicit DENY policies)
deny contains msg if {
	some resource in input.resource_changes
	is_iam_or_role_resource(resource.type)
	not is_deny_policy(resource)

	some permission in get_resource_permissions(resource.change.after)
	contains(permission, "*")

	msg := sprintf("Security violation: Wildcard permission '%v' is prohibited in non-deny statement: %v", [permission, resource.address])
}

# Helpers
is_iam_or_role_resource(res_type) if {
	contains(res_type, "_iam_")
}
is_iam_or_role_resource(res_type) if {
	contains(res_type, "custom_role")
}

is_deny_policy(resource) if {
	contains(lower(resource.type), "deny")
}
is_deny_policy(resource) if {
	lower(resource.change.after.rule_type) == "deny"
}

get_resource_permissions(after) = perms if {
	perms := after.permissions
}
