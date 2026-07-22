@live @cmek
Feature: CMEK Policy for Infrastructure Data at Rest

  As a Security Administrator,
  I want to ensure all infrastructure data at rest is encrypted using Customer Managed Encryption Keys (CMEK)
  So that encryption keys are managed through authorized IaC pipelines using standard Terraform modules.

  Scenario: Symmetric infrastructure encryption must use CMEK/BYOK managed via IaC
    Given the scope is limited to the infrastructure layer
    And the encryption requirement is for symmetric encryption of data at rest
    When resources are provisioned using standard Terraform modules
    And the deployment is managed through Infrastructure as Code (IaC) pipelines
    Then the data must be encrypted using Customer Managed Encryption Keys (CMEK/BYOK)
    And the lifecycle of these keys must be managed by the same IaC pipelines