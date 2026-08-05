@opa @segregation_of_duties
Feature: [E2E Suite] Segregation of Duties & IAM Role Restrictions
  As a GCP security administrator
  I want to enforce segregation of duties in IAM policies
  So that no single identity accumulates conflicting duties or inappropriate permissions

  Scenario: Verify no conflicting duties per principal
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then no principal should hold conflicting duties

  Scenario: Verify pipeline service account permissions
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then pipeline service accounts must only have deployment permissions and no human governance roles

  Scenario: Verify human principal permissions
    Given the GCP project ID is configured
    When I run terraform plan on all modules
    Then human principals must not hold pipeline deployment roles
