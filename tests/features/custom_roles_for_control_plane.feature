@opa @custom_roles @obs_shared
Feature: [E2E Suite] Custom Roles for Control Plane
  As a GCP security administrator
  I want to ensure service accounts and key management utilize custom roles rather than vendor-managed control plane roles
  So that the principle of least privilege is enforced and broad access is restricted

  Scenario: Verify no vendor-managed roles are used for control plane
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then no vendor-managed control-plane roles should be assigned to any resources
    And service accounts must use custom roles instead of vendor-managed control-plane roles

  Scenario: Verify key management role restrictions
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then Vault service accounts must use custom roles for key management

  Scenario: Verify deployment role restrictions
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then CI/CD pipeline service accounts must use custom roles for deployment

  Scenario: Verify custom role definition constraints
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then custom role definitions must enumerate explicit permissions without wildcards
