resource "google_project_service" "logging_api" {
  project            = var.project_id
  service            = "logging.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "bigquery_api" {
  project            = var.project_id
  service            = "bigquery.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "kms_api" {
  project            = var.project_id
  service            = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

module "cmek_log_bucket" {
  source = "../terraform-log-bucket-cmek"

  project_id     = var.project_id
  location       = var.location
  bucket_id      = var.log_bucket_id
  retention_days = var.retention_days
  kms_key_ring   = var.kms_key_ring
  kms_crypto_key = var.kms_crypto_key
}

module "linked_bq_dataset" {
  source = "./modules/linked_bq_dataset"

  project_id        = var.project_id
  bucket_id         = var.log_bucket_id
  bucket_location   = var.location
  linked_dataset_id = var.linked_dataset_id

  description = "Linked BigQuery dataset for HSM CMEK-enabled Log Analytics bucket."
 

  depends_on = [
    module.cmek_log_bucket,
    google_project_service.bigquery_api
  ]
}
