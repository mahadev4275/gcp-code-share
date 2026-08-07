output "log_bucket_id" {
  description = "Log bucket ID created by existing CMEK module."
  value       = var.log_bucket_id
}

output "log_bucket_location" {
  description = "Log bucket location."
  value       = var.location
}

output "linked_dataset_id" {
  description = "Linked BigQuery dataset ID."
  value       = module.linked_bq_dataset.linked_dataset_id
}

output "linked_dataset_name" {
  description = "Full linked BigQuery dataset resource name."
  value       = module.linked_bq_dataset.linked_dataset_name
}