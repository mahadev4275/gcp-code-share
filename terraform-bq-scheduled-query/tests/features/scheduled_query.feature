@CR.SECURITY.034 @CR.SECURITY.035 @CR.ARCHITECTURE.001 @opa
Feature: BigQuery Scheduled Query IAM and Service Account Security
  Requirement ID: CR.SECURITY.034, CR.SECURITY.035, CR.ARCHITECTURE.001
  As a GCP security compliance officer
  I want to ensure Scheduled Query service accounts and IAM bindings follow least privilege and restrict wildcards

  @CR.SECURITY.034-TR-01
  Scenario: Validate service account IAM permissions do not contain wildcards
    Given the scheduled query configuration is inspected
    Then no wildcard action permissions should be assigned to the scheduled query service account

  @CR.SECURITY.035-TR-01
  Scenario: Validate service account is assigned specific roles
    Given the scheduled query service account IAM binding is inspected
    Then the role assigned must be specific and explicitly defined
