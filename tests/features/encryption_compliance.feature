@encryption_compliance
Feature: Encryption Compliance — Key Management Standard
  As a Security Administrator
  I want to ensure all encryption implementations comply with the corporate Key Management Standard
  So that data at rest and data in transit meet approved cryptographic, key lifecycle, and compliance requirements

  Scenario: All symmetric keys must use approved cryptographic algorithms
    Given the GCP project ID is configured
    And the KMS key ring and crypto keys are provisioned
    When the cryptographic algorithm configuration is inspected
    Then all symmetric keys must use AES-256-GCM
    And no non-approved algorithms must be present

  Scenario: All symmetric keys must meet minimum bit strength
    Given the GCP project ID is configured
    And the KMS key ring and crypto keys are provisioned
    When the key bit strength is inspected
    Then all symmetric keys must have a minimum strength of 256 bits

  Scenario: Production data-at-rest keys must use CloudHSM for FIPS 140-2 Level 3
    Given the GCP project ID is configured
    And the KMS key ring and crypto keys are provisioned
    When the key protection level is inspected
    Then all production data-at-rest keys must use CloudHSM protection level
    And the CloudHSM module must meet FIPS 140-2 Level 3 certification

  Scenario: Key rotation must be enabled and within policy limits
    Given the GCP project ID is configured
    And the KMS key ring and crypto keys are provisioned
    When the key rotation configuration is inspected
    Then automatic key rotation must be enabled
    And the rotation period must not exceed 365 days
    And the next rotation time must be scheduled

  Scenario: KMS API endpoints must enforce TLS 1.2 or higher
    Given the GCP project ID is configured
    When the encryption-in-transit posture is validated against the key management standard
    Then all KMS API endpoints must enforce TLS 1.2 or higher
    And legacy TLS versions must be rejected by KMS endpoints

  Scenario: Key lifecycle must be managed through Infrastructure as Code
    Given the GCP project ID is configured
    And key resources are provisioned through Infrastructure as Code
    Then KMS key rings must be present in the Terraform state
    And KMS crypto keys must be present in the Terraform state
    And organization policies for CMEK must be enforced via IaC
