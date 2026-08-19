variable "project_id" {
  description = "GCP project ID where the Cloud Logging bucket exists."
  type        = string
}

variable "bucket_id" {
  description = "Cloud Logging bucket ID."
  type        = string
}

variable "bucket_location" {
  description = "Location of the Cloud Logging bucket."
  type        = string
}

variable "linked_dataset_id" {
  description = "Linked BigQuery dataset ID."
  type        = string
}

variable "description" {
  description = "Description for the linked BigQuery dataset."
  type        = string
  default     = "Linked BigQuery dataset for Log Analytics."
}

variable "kms_key_ring" {
  type    = string
  default = "logging-keyring-bq"
}

variable "kms_crypto_key" {
  type    = string
  default = "logging-key-bq"
}