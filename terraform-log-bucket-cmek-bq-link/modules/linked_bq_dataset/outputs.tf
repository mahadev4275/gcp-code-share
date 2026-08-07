output "linked_dataset_id" {
  description = "Linked BigQuery dataset ID."
  value       = google_logging_linked_dataset.linked_dataset.link_id
}

output "linked_dataset_name" {
  description = "Full linked BigQuery dataset resource name."
  value       = google_logging_linked_dataset.linked_dataset.name
}

output "linked_dataset_resource_id" {
  description = "Terraform resource ID."
  value       = google_logging_linked_dataset.linked_dataset.id
}