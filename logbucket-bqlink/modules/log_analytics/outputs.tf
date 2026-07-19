output "bucket_name" {
  value = google_logging_project_bucket_config.bucket.name
}

output "linked_dataset" {
  value = google_logging_linked_dataset.linked_dataset.name
}

output "bigquery_dataset" {
  value = google_logging_linked_dataset.linked_dataset.bigquery_dataset
}
