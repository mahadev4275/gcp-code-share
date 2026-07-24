package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny disabled or invalid monitoring project service (CR.ARCHITECTURE.001)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_project_service"

	service := resource.change.after.service
	service != "monitoring.googleapis.com"

	msg := sprintf("Security violation (CR.ARCHITECTURE.001): Invalid or non-GA monitoring service '%v'", [service])
}

# 2. Deny alert policy with zero periodicity or disabled status (CR.SECURITY.002)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_monitoring_alert_policy"

	enabled := object.get(resource.change.after, "enabled", true)
	enabled == false

	msg := sprintf("Security violation (CR.SECURITY.002): Monitoring alert policy '%v' is disabled", [resource.address])
}
