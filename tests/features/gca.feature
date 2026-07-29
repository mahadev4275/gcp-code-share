@gca
Feature: Gemini for Google Cloud API (GCA) Compliance Verification
  As a GCP Security Administrator
  I want to verify that Gemini for Google Cloud API (cloudaicompanion.googleapis.com) meets all architecture and security standards
  So that high criticality and sensitive workloads operate in a fully compliant environment

  @live @architecture_ga
  Scenario: Verify GCA API enablement and General Availability status
    Given the GCP project ID is configured
    When I evaluate compliance for "General Availability Service Status"
    And I check the status of the "cloudaicompanion.googleapis.com" API
    Then the API state must be "ENABLED"
    And all enabled GCA APIs must have at least one General Availability version

  @live @encryption_in_transit
  Scenario: Verify GCA API transport security and HTTPS TLS 1.2+ enforcement
    Given the GCP project ID is configured
    When I evaluate compliance for "Data in Transit Encryption Enforcement"
    Then the GCA API endpoint "cloudaicompanion.googleapis.com" must enforce HTTPS
    And legacy TLS versions (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) must be rejected

  @live @cmek_encryption
  Scenario: Verify CloudHSM CMEK encryption and key rotation for GCA data at rest
    Given the GCP project ID is configured
    When I evaluate compliance for "Customer Managed Encryption Key Compliance"
    Then GCA data stores and telemetry logs must use CloudHSM protection level
    And automatic key rotation must be enabled with a period not exceeding 365 days

  @live @iam_least_privilege
  Scenario: Audit live GCA IAM policy bindings for least privilege
    Given the GCP project ID is configured
    When I evaluate compliance for "IAM Least Privilege Access Restriction"
    Then GCA service account bindings must explicitly enumerate permissions
    And no wildcard permissions or wildcard roles must be granted to GCA identities

  @opa @custom_roles
  Scenario: Verify custom roles for GCA control plane service accounts
    Given the GCP project ID is configured
    When I evaluate compliance for "Custom Roles for Control Plane"
    And I run terraform plan on all GCA modules
    Then GCA service accounts must use custom roles instead of broad vendor-managed roles

  @opa @public_access_prevention
  Scenario: Verify GCA storage and logging public access prevention
    Given the GCP project ID is configured
    When I evaluate compliance for "Storage Public Access Prevention"
    And I inspect GCA storage buckets and logging configurations
    Then no GCA log bucket or storage resource shall allow allUsers or allAuthenticatedUsers access
    And public access prevention must be enforced

  @live @network_boundary_security
  Scenario: Verify GCA network exposure prevention and perimeter controls
    Given the GCP project ID is configured
    When I evaluate compliance for "Network Boundary Security Exposure Prevention"
    Then GCA endpoints and associated resources must operate without public IP exposure
    And VPC boundary security controls must be active
