@CR.SECURITY.034 @CR.SECURITY.037 @opa @bigquery
Feature: [BigQuery Cross-Project] IAM Access & Public Access Compliance
  Requirement ID: CR.SECURITY.034, CR.SECURITY.037
  As a GCP security administrator
  I want to ensure BigQuery dataset IAM members adhere to least privilege and prevent public access

  @CR.SECURITY.034-TR-01
  Scenario: [BigQuery Cross-Project] Validate IAM permissions do not use wildcards
    Given the BigQuery dataset IAM member configuration is inspected
    Then no wildcard permissions should be granted in IAM bindings

  @CR.SECURITY.037-TR-01
  Scenario: [BigQuery Cross-Project] Validate BigQuery dataset IAM does not permit public access
    Given the BigQuery dataset IAM member configuration is inspected
    Then no public members like allUsers or allAuthenticatedUsers should be granted access
