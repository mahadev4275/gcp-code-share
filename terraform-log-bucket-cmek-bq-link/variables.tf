variable "project_id" {
  description = "GCP project ID where the HSM CMEK log bucket will be created."
  type        = string
}

variable "location" {
  description = "Location for the log bucket and KMS resources."
  type        = string
  default     = "us-central1"
}

variable "log_bucket_id" {
  description = "Name of the HSM CMEK-enabled Log Analytics bucket."
  type        = string
  default     = "observability-log-bucket"
}

variable "retention_days" {
  description = "Retention period for the log bucket."
  type        = number
  default     = 30
}

variable "linked_dataset_id" {
  description = "Linked BigQuery dataset ID. Use only letters, numbers, and underscores."
  type        = string
  default     = "log_analytics_dataset"

  validation {
    condition     = can(regex("^[A-Za-z0-9_]{1,100}$", var.linked_dataset_id))
    error_message = "linked_dataset_id must contain only letters, numbers, and underscores. Do not use hyphens."
  }
}