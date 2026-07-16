Feature: GCP Observability API Enablement Check
  As a GCP administrator
  I want to ensure that the observability API (Cloud Trace) is enabled
  So that tracing and monitoring are active for the project

  Scenario: Verify Cloud Trace API is enabled
    Given the GCP project ID is configured
    When I check the status of the Cloud Trace API
    Then the Cloud Trace API state should be "ENABLED"
