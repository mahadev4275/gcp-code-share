package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 1. Deny GCS Storage Buckets that do not use Customer Managed Encryption Keys (CMEK)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_storage_bucket"
	
	encryption := resource.change.after.encryption
	not is_cmek_encryption_configured(encryption)
	
	msg := sprintf("Security violation: Storage bucket '%v' is not using CMEK (encryption.default_kms_key_name is missing)", [resource.address])
}

# 2. Deny KMS Crypto Keys without rotation_period (Lifecycle management via IaC)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_kms_crypto_key"
	
	rotation := resource.change.after.rotation_period
	not rotation
	
	msg := sprintf("Security violation: KMS Crypto Key '%v' must specify a rotation_period for key lifecycle management", [resource.address])
}

# Helpers
is_cmek_encryption_configured(encryption) if {
	encryption[0].default_kms_key_name != ""
}
