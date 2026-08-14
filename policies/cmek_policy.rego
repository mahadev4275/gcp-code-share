package cmek

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

# 2. Deny BigQuery Datasets that do not use Customer Managed Encryption Keys (CMEK)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_dataset"
	
	enc := resource.change.after.default_encryption_configuration
	not is_bq_cmek_configured(enc)
	
	msg := sprintf("Security violation: BigQuery dataset '%v' is not using CMEK (default_encryption_configuration.kms_key_name is missing)", [resource.address])
}

# 3. Deny BigQuery Tables that do not use Customer Managed Encryption Keys (CMEK)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_bigquery_table"
	
	enc := resource.change.after.encryption_configuration
	not is_bq_table_cmek_configured(enc)
	
	msg := sprintf("Security violation: BigQuery table '%v' is not using CMEK (encryption_configuration.kms_key_name is missing)", [resource.address])
}

# 4. Deny Logging Buckets that do not use Customer Managed Encryption Keys (CMEK)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_logging_project_bucket_config"
	
	cmek := resource.change.after.cmek_settings
	not is_logging_cmek_configured(cmek)
	
	msg := sprintf("Security violation: Logging bucket '%v' is not using CMEK (cmek_settings.kms_key_name is missing)", [resource.address])
}

# 5. Deny PubSub Topics that do not use Customer Managed Encryption Keys (CMEK)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_pubsub_topic"
	
	kms := resource.change.after.kms_key_name
	not is_str_kms_configured(kms)
	
	msg := sprintf("Security violation: PubSub topic '%v' is not using CMEK (kms_key_name is missing)", [resource.address])
}

# 6. Deny Cloud SQL Instances that do not use Customer Managed Encryption Keys (CMEK)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_sql_database_instance"
	
	settings := resource.change.after.settings
	not is_sql_cmek_configured(settings)
	
	msg := sprintf("Security violation: Cloud SQL instance '%v' is not using CMEK (settings.encryption_kms_key_name is missing)", [resource.address])
}

# 7. Deny Compute Disks that do not use Customer Managed Encryption Keys (CMEK)
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "google_compute_disk"
	
	key := resource.change.after.disk_encryption_key
	not is_disk_cmek_configured(key)
	
	msg := sprintf("Security violation: Compute disk '%v' is not using CMEK (disk_encryption_key.kms_key_name is missing)", [resource.address])
}

# 8. Deny KMS Crypto Keys without rotation_period (Lifecycle management via IaC)
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

is_bq_cmek_configured(enc) if {
	enc[0].kms_key_name != ""
}

is_bq_table_cmek_configured(enc) if {
	enc[0].kms_key_name != ""
}

is_logging_cmek_configured(cmek) if {
	cmek[0].kms_key_name != ""
}

is_str_kms_configured(kms) if {
	kms != ""
}

is_sql_cmek_configured(settings) if {
	settings[0].encryption_kms_key_name != ""
}

is_disk_cmek_configured(key) if {
	key[0].kms_key_name != ""
}
