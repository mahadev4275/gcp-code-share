output "bucket_name" {
  value = google_logging_project_bucket_config.cmek_bucket.bucket_id
}

output "bucket_resource_name" {
  value = google_logging_project_bucket_config.cmek_bucket.id
}

output "kms_key" {
  value = google_kms_crypto_key.logging.id
}

output "kms_key_ring_name" {
  value = google_kms_key_ring.logging.name
}

output "kms_crypto_key_name" {
  value = google_kms_crypto_key.logging.name
}