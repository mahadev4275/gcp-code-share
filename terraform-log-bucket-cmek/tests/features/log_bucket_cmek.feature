@CR.SECURITY.009 @CR.SECURITY.034 @CR.SECURITY.037 @opa
Feature: Dedicated CMEK Logging Bucket Compliance
  Requirement ID: CR.SECURITY.009, CR.SECURITY.034, CR.SECURITY.037
  As a GCP Security Compliance Lead
  I want to ensure the dedicated CMEK Logging Bucket uses KMS key rings, automatic key rotation, and strict IAM controls

  @CR.SECURITY.009-TR-01
  Scenario: Validate Logging Bucket specifies valid CMEK settings and KMS key rotation
    Given the dedicated CMEK logging bucket configuration is inspected
    Then cmek_settings must be present on the logging bucket
    And KMS crypto key rotation period must not exceed 365 days

  @CR.SECURITY.034-TR-01
  Scenario: Validate KMS Crypto Key IAM binding does not use wildcards
    Given the KMS crypto key IAM binding is inspected
    Then no wildcard permissions or public members must be granted
