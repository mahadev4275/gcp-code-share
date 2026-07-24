package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# Deny Org Policy for gcp.resourceLocations if allowed_values is empty (CR.ARCHITECTURE.001)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_org_policy_policy"
	contains(resource.change.after.name, "gcp.resourceLocations")

	rules := resource.change.after.spec[0].rules
	count(rules) > 0
	values := rules[0].values[0].allowed_values
	count(values) == 0

	msg := sprintf("Security violation (CR.ARCHITECTURE.001): Org policy '%v' has empty allowed_values", [resource.address])
}
