@live @GA
Feature: [E2E Suite] GCP APIs General Availability Check
  As a GCP administrator
  I want to ensure all enabled APIs in the project are in General Availability (GA)
  So that the project does not rely on preview or beta features in production

 #Scenario: Verify all enabled GCP APIs are in General Availability (GA) status
 #   Given the GCP project ID is configured
 #   When I list the enabled services in the project
 #   And I retrieve the Google Cloud APIs Discovery document
 #   Then all enabled APIs should have at least one General Availability version

  
  Scenario: Verify Cloud API is enabled
    Given the GCP project ID is configured
    When I check the status of "<api>" API
    Then the API state should be "<state>"

    Examples:
    | api                   | state            |
    | observability         | ENABLED          |
    | geminicloudassist     | ENABLED          |
    | cloudaicompanion      | ENABLED          |
