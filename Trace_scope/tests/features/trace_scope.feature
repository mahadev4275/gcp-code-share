@CR.ARCHITECTURE.001 @CR.SECURITY.002 @opa
Feature: [Trace Scope Wrapper] Module Sub-Module Invocation
  Requirement ID: CR.ARCHITECTURE.001, CR.SECURITY.002
  As a GCP Observability Architect
  I want to ensure the Trace Scope module wrapper configures trace scope resources properly

  @CR.ARCHITECTURE.001-TR-01
  Scenario: [Trace Scope Wrapper] Validate Trace Scope wrapper invokes sub-module with required variables
    Given the trace scope wrapper module configuration is inspected
    Then the trace scope resource should be planned for creation
