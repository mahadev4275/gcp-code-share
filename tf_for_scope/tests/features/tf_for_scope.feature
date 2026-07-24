@CR.ARCHITECTURE.001 @CR.SECURITY.002 @opa
Feature: Observability Trace Scope Compliance
  Requirement ID: CR.ARCHITECTURE.001, CR.SECURITY.002
  As a Cloud Observability Engineer
  I want to ensure Observability Trace Scope resources are configured according to architecture guidelines

  @CR.ARCHITECTURE.001-TR-01
  Scenario: Validate Observability Trace Scope is configured with valid resource scope names
    Given the trace scope configuration is inspected
    Then the trace scope resource names must be valid project resource URIs
