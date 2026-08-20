provider "google" {
  project = var.project_id
}

##########################################################
# Project Details
##########################################################

data "google_project" "current" {
  project_id = var.project_id
}

##########################################################
# Logging CMEK Service Account
##########################################################

data "google_logging_project_cmek_settings" "cmek_settings" {
  project = var.project_id
}

##########################################################
# KMS Key Ring
##########################################################

resource "google_kms_key_ring" "logging" {
  name     = var.kms_key_ring
  location = var.location
}

##########################################################
# KMS Crypto Key For Logging Bucket CMEK
##########################################################

resource "google_kms_crypto_key" "logging" {
  name            = var.kms_crypto_key
  key_ring        = google_kms_key_ring.logging.id
  rotation_period = "7776000s"
  version_template {
    protection_level = "HSM"
    algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  }
  lifecycle {
    prevent_destroy = false
  }
}

##########################################################
# Grant Cloud Logging CMEK Service Account Access To KMS
##########################################################

resource "google_kms_crypto_key_iam_member" "logging_cmek_sa" {
  crypto_key_id = google_kms_crypto_key.logging.id

  role = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  member = "serviceAccount:${data.google_logging_project_cmek_settings.cmek_settings.service_account_id}"

  condition {
    title       = "restrict_to_logging_cmek_key"
    description = "Scope encrypt/decrypt access to the logging CMEK key only"
    expression  = "resource.name.endsWith(\"keyRings/${var.kms_key_ring}/cryptoKeys/${var.kms_crypto_key}\")"
  }
}



##########################################################
# Cloud Logging Bucket With CMEK
##########################################################

resource "google_logging_project_bucket_config" "cmek_bucket" {
  project = var.project_id

  # IMPORTANT:
  # This location must match the KMS key location.
  location = var.location

  bucket_id      = var.bucket_id
  retention_days = var.retention_days
  enable_analytics = true

  cmek_settings {
    kms_key_name = google_kms_crypto_key.logging.id
  }

  depends_on = [
    google_kms_crypto_key_iam_member.logging_cmek_sa
  ]
}

