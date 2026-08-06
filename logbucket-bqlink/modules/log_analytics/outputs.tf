output "bucket_name" {
  value = google_logging_project_bucket_config.analytics_bucket.name
}

output "kms_key" {
  value = google_kms_crypto_key.log_key.id
}

output "linked_dataset" {
  value = google_logging_linked_dataset.analytics_dataset.name
}