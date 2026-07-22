@live @iam_restrictions
Feature: IAM Permission Restrictions Check
  As a GCP security administrator
  I want to ensure IAM permission restrictions are enforced in Terraform configurations
  So that privilege escalation, public access, and cross-environment access are prevented

  Scenario: Verify no wildcard permissions are allowed in IAM policies
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then no wildcard principals, wildcard roles, or wildcard permissions should be allowed

  Scenario: Verify conditional scoping at trust boundary
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then all IAM resources must include a condition block
    And no organization-level IAM bindings are allowed

  Scenario: Verify service account scope restrictions
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then service account bindings must be folder or project scoped
    And no cross-environment service account access should be detected

  Scenario: Verify TFE pipeline service account permission restrictions
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then pipeline service accounts must not be granted wildcard, owner, editor, or data-plane roles
