@CR.SECURITY.009 @CR.SECURITY.034 @CR.SECURITY.002 @opa @bigquery
Feature: [Log Router BQ] BigQuery Sink CMEK & IAM Least Privilege
  Requirement ID: CR.SECURITY.009, CR.SECURITY.034, CR.SECURITY.002
  As a GCP log security officer
  I want to ensure BigQuery log sink destinations enforce CMEK encryption and IAM least privilege

  @CR.SECURITY.009-TR-01
  Scenario: [Log Router BQ] Validate BigQuery dataset for log router specifies CMEK encryption
    Given the BigQuery log router dataset configuration is inspected
    Then default_encryption_configuration with KMS key name should be configured

  @CR.SECURITY.034-TR-01
  Scenario: [Log Router BQ] Validate Log Sink writer identity IAM binding does not use wildcards
    Given the Log Sink writer identity IAM binding is inspected
    Then no wildcard permissions should be granted to the sink writer identity
