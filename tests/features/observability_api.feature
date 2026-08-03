@live @obs_api
Feature: [E2E Suite] GCP Observability API Enablement Check
  As a GCP administrator
  I want to ensure that the observability API is enabled
  So that tracing and monitoring are active for the project

  Scenario: Verify Cloud Trace API is enabled
    Given the GCP project ID is configured
    When I check the status of "<api>" API
    Then the Observability API state should be "<state>"

    Examples:
    | api                   | state            |
    | observability         | ENABLED          |
    | geminicloudassist     | ENABLED          |
    | cloudaicompanion      | ENABLED          |
