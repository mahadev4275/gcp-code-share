resource "google_bigquery_dataset_iam_member" "member" {

  for_each = var.members

  project    = var.project_id
  dataset_id = var.dataset_id

  role   = var.role
  member = each.value
}