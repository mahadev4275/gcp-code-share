@opa @public_access @bigquery @observability
Feature: [E2E Suite] GCP Resource Public Access Prevention Check
  As a GCP administrator
  I want to ensure that logging, tracing, and observability bucket data are not public
  So that sensitive logs and telemetry are protected

  Scenario: Verify Log Buckets and GCS Storage Buckets do not have public IAM permissions
    Given the GCP project ID is configured
    And the test runner has sufficient GCP IAM privileges
    When I inspect the IAM policies of all Log Views and GCS Storage Buckets in the project
    Then no Log View or GCS Storage Bucket should be accessible to allUsers or allAuthenticatedUsers

  Scenario: Verify Storage Public Access Prevention Org Policy is enforced
    Given the GCP project ID is configured
    And the test runner has sufficient GCP IAM privileges
    When I retrieve the effective Org Policy for Storage Public Access Prevention
    Then the Public Access Prevention policy should be enforced

  Scenario: Verify Cloud Logging is protected by VPC Service Controls
    Given the GCP project ID is configured
    And the test runner has sufficient GCP IAM privileges
    When I check the VPC Service Perimeters for the project
    Then Cloud Logging should be protected by a perimeter
