data "google_project" "current" {
 
  project_id = var.project_id
 
}
 
resource "google_kms_crypto_key_iam_member" "bq_encrypter_decrypter" {
 
  crypto_key_id = google_kms_crypto_key.log_router_key.id
 
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
 
  member        = "serviceAccount:bq-${data.google_project.current.number}@bigquery-encryption.iam.gserviceaccount.com"
 
  condition {
    title       = "restrict_to_log_router_key"
    description = "Scope encrypt/decrypt access to the log router CMEK key only"
    expression  = "resource.name == \"${google_kms_crypto_key.log_router_key.id}\""
  }
 
}
 
# CMEK for above BQ logs
 
resource "google_kms_key_ring" "log_router_keyring" {
 
  name     = "log-router-keyring1"
 
  location = "us" # KMS key location must match the BigQuery dataset's location
 
  # project  = var.project_id
 
}
 
resource "google_kms_crypto_key" "log_router_key" {
 
  name     = "log-router-cmek-key"
 
  key_ring = google_kms_key_ring.log_router_keyring.id
 
  # Optional but recommended: rotate every 90 days
 
  rotation_period = "7776000s"
 
  # lifecycle {
 
  #   prevent_destroy = true  # avoid accidentally destroying a key in use
 
  # }
 
}
 
 
# Creation of Bigquery dataset
 
resource "google_bigquery_dataset" "logs" {
 
  project    = var.project_id
 
  dataset_id = var.dataset_id
 
  location   = "US"
 
  default_encryption_configuration {
 
    kms_key_name = google_kms_crypto_key.log_router_key.id
 
  }
 
  depends_on = [
 
    google_kms_crypto_key_iam_member.bq_encrypter_decrypter
 
  ]
 
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
 
  condition {
    title       = "restrict_to_logs_dataset"
    description = "Scope dataEditor access to the logs dataset only, and only for the sink's writer identity"
    expression  = "resource.name == \"projects/${var.project_id}/datasets/${google_bigquery_dataset.logs.dataset_id}\""
  }
 
}