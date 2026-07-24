package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# Deny google_observability_trace_scope if resource_names is empty (CR.ARCHITECTURE.001)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_observability_trace_scope"

	names := resource.change.after.resource_names
	count(names) == 0

	msg := sprintf("Security violation (CR.ARCHITECTURE.001): Trace Scope '%v' has empty resource_names list", [resource.address])
}
