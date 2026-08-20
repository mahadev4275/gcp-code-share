resource "google_bigquery_dataset_iam_member" "member" {

  for_each = var.members

  project    = var.project_id
  dataset_id = var.dataset_id

  role   = var.role
  member = each.value

  condition {
    title       = "restrict_to_dataset"
    description = "Scope cross-project access to the specific BigQuery dataset only"
    expression  = "resource.name == \"projects/${var.project_id}/datasets/${var.dataset_id}\""
  }
}