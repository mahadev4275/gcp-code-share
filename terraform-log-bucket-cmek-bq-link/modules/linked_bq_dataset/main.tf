resource "google_logging_linked_dataset" "linked_dataset" {
  link_id     = var.linked_dataset_id
  bucket      = var.bucket_id
  parent      = "projects/${var.project_id}"
  location    = var.bucket_location
  description = var.description
}