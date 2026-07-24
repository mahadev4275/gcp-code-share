package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# Deny Org Policy for restrictNonCmekServices if allowed_values is empty (CR.SECURITY.009)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_org_policy_policy"
	contains(resource.change.after.name, "gcp.restrictNonCmekServices")

	rules := resource.change.after.spec[0].rules
	count(rules) > 0
	values := rules[0].values[0].allowed_values
	count(values) == 0

	msg := sprintf("Security violation (CR.SECURITY.009): Org Policy '%v' restricts non-CMEK services but specifies an empty allowed_values list", [resource.address])
}
