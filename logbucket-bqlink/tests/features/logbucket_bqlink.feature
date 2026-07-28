@CR.SECURITY.009 @CR.SECURITY.037 @CR.ARCHITECTURE.001 @opa
Feature: [Log Bucket BQ Link] Security & CMEK Encryption
  Requirement ID: CR.SECURITY.009, CR.SECURITY.037, CR.ARCHITECTURE.001
  As a GCP cloud architect
  I want to ensure Logging Buckets and BigQuery Linked Datasets enforce CMEK and public access restrictions

  @CR.SECURITY.009-TR-01
  Scenario: [Log Bucket BQ Link] Validate Logging Bucket specifies CMEK key settings
    Given the logging bucket configuration is inspected
    Then cmek_settings with a valid KMS key name must be configured for the logging bucket

  @CR.SECURITY.037-TR-01
  Scenario: [Log Bucket BQ Link] Validate Logging Bucket does not allow public access
    Given the logging bucket configuration is inspected
    Then no public IAM bindings should be present on the logging bucket
