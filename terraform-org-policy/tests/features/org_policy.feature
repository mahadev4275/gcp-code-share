@CR.ARCHITECTURE.001 @CR.SECURITY.009 @opa
Feature: [Resource Location Policy] Location Constraint Compliance
  Requirement ID: CR.ARCHITECTURE.001, CR.SECURITY.009
  As a GCP security administrator
  I want to ensure resource location organization policies explicitly list allowed geographic regions

  @CR.ARCHITECTURE.001-TR-01
  Scenario: [Resource Location Policy] Validate Resource Locations Org Policy specifies allowed location constraints
    Given the resource locations org policy configuration is inspected
    Then allowed values for resource locations must be non-empty
