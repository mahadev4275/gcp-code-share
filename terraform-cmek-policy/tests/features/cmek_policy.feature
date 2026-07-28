@CR.SECURITY.009 @CR.ARCHITECTURE.001 @opa
Feature: [CMEK Org Policy] Restriction Org Policy Compliance
  Requirement ID: CR.SECURITY.009, CR.ARCHITECTURE.001
  As a GCP security architect
  I want to ensure non-CMEK services are restricted via organization policy

  @CR.SECURITY.009-TR-01
  Scenario: [CMEK Org Policy] Validate CMEK restriction Org Policy is configured
    Given the CMEK org policy configuration is inspected
    Then allowed non-CMEK services list must be explicitly specified
