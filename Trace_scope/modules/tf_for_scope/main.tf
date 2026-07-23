resource "google_observability_trace_scope" "observability_trace_scope" {
  trace_scope_id = "test_scope"
  location       = var.location

  resource_names = [
    for project_id in var.projects :
    "projects/${project_id}"
  ]

  description = "A trace scope configured with Terraform"
}
