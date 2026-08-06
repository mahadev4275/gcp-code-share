####################################################
# Enable APIs
####################################################

resource "google_project_service" "logging" {
  service = "logging.googleapis.com"
}

resource "google_project_service" "bigquery" {
  service = "bigquery.googleapis.com"
}

resource "google_project_service" "kms" {
  service = "cloudkms.googleapis.com"
}

resource "google_kms_key_ring" "log_keyring" {

  name     = "log-keyring"
  location = var.location
}

resource "google_kms_crypto_key" "log_key" {

  name     = "log-bucket-key"

  key_ring = google_kms_key_ring.log_keyring.id

  rotation_period = "7776000s"
}

data "google_logging_project_cmek_settings" "this" {
  project = var.project_id
}

resource "google_kms_crypto_key_iam_member" "logging_sa" {

  crypto_key_id = google_kms_crypto_key.log_key.id

  role = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  member = "serviceAccount:${data.google_logging_project_cmek_settings.this.service_account_id}"
}

resource "google_logging_project_bucket_config" "analytics_bucket" {

  project = var.project_id

  location = var.location

  bucket_id = var.bucket_id

  retention_days = 30

  enable_analytics = true

  cmek_settings {
    kms_key_name = google_kms_crypto_key.log_key.id
  }

  depends_on = [
    google_kms_crypto_key_iam_member.logging_sa
  ]
}

resource "google_logging_linked_dataset" "analytics_dataset" {

  bucket = google_logging_project_bucket_config.analytics_bucket.id

  link_id = var.dataset_id

  description = "Linked BigQuery dataset for Log Analytics"

  depends_on = [
    google_logging_project_bucket_config.analytics_bucket
  ]
}

