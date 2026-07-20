# Creation of Bigquery dataset
resource "google_bigquery_dataset" "logs" {

  project    = var.project_id
  dataset_id = var.dataset_id
  location   = "US"
}

# Creation of an Log router Sink
resource "google_logging_project_sink" "logs_to_bq" {

  name    = var.sink_name
  project = var.project_id

  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.logs.dataset_id}"

  unique_writer_identity = true
}

# IAM permission required for the sink identity to write to the BQ dataset
resource "google_bigquery_dataset_iam_member" "sink_writer" {

  dataset_id = google_bigquery_dataset.logs.dataset_id

  role = "roles/bigquery.dataEditor"

  member = google_logging_project_sink.logs_to_bq.writer_identity
}