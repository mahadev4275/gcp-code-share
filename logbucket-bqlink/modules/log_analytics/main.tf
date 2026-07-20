###################################################
# Logging Bucket with Log Analytics
###################################################

resource "google_logging_project_bucket_config" "bucket" {

  project        = var.project_id
  location       = var.location
  bucket_id      = var.bucket_id

  retention_days = var.retention_days

  enable_analytics = true

  description = "Observability Log Analytics Bucket"
}

###################################################
# Linked Dataset
###################################################

resource "google_logging_linked_dataset" "linked_dataset" {

  bucket = google_logging_project_bucket_config.bucket.id

  link_id = var.link_id

  description = "Linked BigQuery Dataset for Log Analytics"

  depends_on = [
    google_logging_project_bucket_config.bucket
  ]
}