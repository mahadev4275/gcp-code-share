variable "project_id" {
  type = string
}

variable "location" {
  type    = string
  default = "us-central1"
}

variable "bucket_id" {
  type    = string
  default = "central-logs"
}

variable "retention_days" {
  type    = number
  default = 30
}

variable "kms_key_ring" {
  type    = string
  #default = "logging-keyring"
}

variable "kms_crypto_key" {
  type    = string
  #default = "logging-key"
}