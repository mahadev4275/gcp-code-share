@CR.ARCHITECTURE.001 @CR.SECURITY.002 @opa
Feature: Monitoring SQL Alert Policy Compliance
  Requirement ID: CR.ARCHITECTURE.001, CR.SECURITY.002
  As a GCP Observability Architect
  I want to ensure Cloud Monitoring SQL alerts use GA APIs and valid alert policy configurations

  @CR.ARCHITECTURE.001-TR-01
  Scenario: Validate Cloud Monitoring API enablement service
    Given the SQL alert monitoring configuration is inspected
    Then the enabled service must be monitoring.googleapis.com

  @CR.SECURITY.002-TR-01
  Scenario: Validate SQL alert policy notification channel and periodicity
    Given the SQL alert policy condition is inspected
    Then periodicity must be positive and notification email must be configured
