package encryption 

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# -----------------------------------------------------------------------------
# 1. Load Balancer SSL Policy Compliance
# -----------------------------------------------------------------------------

# SSL Policy Profile must be MODERN or RESTRICTED
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_compute_ssl_policy"
	
	profile := resource.change.after.profile
	not profile in ["MODERN", "RESTRICTED"]
	
	msg := sprintf("Security violation: SSL Policy '%v' profile '%v' is non-compliant (must be MODERN or RESTRICTED)", [resource.address, profile])
}

# SSL Policy Min TLS Version must be TLS_1_2
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_compute_ssl_policy"
	
	min_ver := resource.change.after.min_tls_version
	min_ver != "TLS_1_2"
	
	msg := sprintf("Security violation: SSL Policy '%v' min_tls_version '%v' is non-compliant (must be TLS_1_2)", [resource.address, min_ver])
}

# -----------------------------------------------------------------------------
# 2. Database TLS Enforcement
# -----------------------------------------------------------------------------

# Cloud SQL require_ssl must be true
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_sql_database_instance"
	
	ip_config := resource.change.after.settings[_].ip_configuration[_]
	ip_config.require_ssl != true
	
	msg := sprintf("Security violation: Cloud SQL instance '%v' has require_ssl set to false", [resource.address])
}

# Cloud SQL ssl_mode must enforce TLS
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_sql_database_instance"
	
	ip_config := resource.change.after.settings[_].ip_configuration[_]
	ssl_mode := ip_config.ssl_mode
	not ssl_mode in ["TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "ENCRYPTED_ONLY", ""]
	
	msg := sprintf("Security violation: Cloud SQL instance '%v' has insecure ssl_mode '%v'", [resource.address, ssl_mode])
}

# Cloud SQL ssl_min_protocol_version flag must be TLSv1.2 or higher
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_sql_database_instance"
	
	flag := resource.change.after.settings[_].database_flags[_]
	lower(flag.name) == "ssl_min_protocol_version"
	not flag.value in ["TLSv1.2", "TLSv1.3"]
	
	msg := sprintf("Security violation: Cloud SQL instance '%v' has insecure ssl_min_protocol_version '%v'", [resource.address, flag.value])
}

# -----------------------------------------------------------------------------
# 3. Service-to-Service Encryption & Internal Traffic
# -----------------------------------------------------------------------------

# Compute Backend Services must use HTTPS, HTTP2, or GRPC protocol
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_compute_backend_service"
	
	protocol := resource.change.after.protocol
	protocol == "HTTP"
	
	msg := sprintf("Security violation: Compute Backend Service '%v' uses unencrypted protocol 'HTTP'", [resource.address])
}

# Cloud Run Services must restrict ingress to internal/load balancing
deny contains msg if {
	some resource in input.resource_changes
	resource.type in ["google_cloud_run_v2_service", "google_cloud_run_service"]
	
	ingress := resource.change.after.ingress
	ingress == "INGRESS_TRAFFIC_ALL"
	
	msg := sprintf("Security violation: Cloud Run Service '%v' has unrestricted ingress 'INGRESS_TRAFFIC_ALL'", [resource.address])
}

# -----------------------------------------------------------------------------
# 4. Insecure URL Schemes Prevention (http://, ws://, ftp://, telnet://)
# -----------------------------------------------------------------------------

deny contains msg if {
	some resource in input.resource_changes
	walk(resource.change.after, [_, val])
	is_string(val)
	
	scheme := get_insecure_scheme(val)
	scheme != ""
	
	msg := sprintf("Security violation: Resource '%v' contains URL with insecure scheme '%v': %v", [resource.address, scheme, val])
}

# Helper: Check if string starts with an insecure URL scheme
get_insecure_scheme(str) = "http://" if startswith(lower(str), "http://")
get_insecure_scheme(str) = "ws://" if startswith(lower(str), "ws://")
get_insecure_scheme(str) = "ftp://" if startswith(lower(str), "ftp://")
get_insecure_scheme(str) = "telnet://" if startswith(lower(str), "telnet://")

# -----------------------------------------------------------------------------
# 5. Observability & API Endpoint Scheme & TLS 1.2+ Policy
# -----------------------------------------------------------------------------

# Reject HTTP scheme or insecure endpoints for Observability & API resources
deny contains msg if {
	some resource in input.resource_changes
	is_observability_api_resource(resource.type)

	scheme := get_insecure_scheme(resource.change.after.url)
	scheme != ""

	msg := sprintf("Security violation: Observability API endpoint '%v' uses unsafe scheme '%v' (must be https:// with TLS 1.2+)", [resource.address, scheme])
}

is_observability_api_resource(res_type) if {
	contains(res_type, "api_gateway")
}
is_observability_api_resource(res_type) if {
	contains(res_type, "endpoints_service")
}
is_observability_api_resource(res_type) if {
	contains(res_type, "cloud_run")
}

