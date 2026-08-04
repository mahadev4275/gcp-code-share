@gca @live
Feature: Gemini for Google Cloud API (GCA) Compliance Verification
  As a GCP Security Administrator
  I want to verify that Gemini for Google Cloud API (cloudaicompanion.googleapis.com) meets all live API architecture and security standards
  So that high criticality and sensitive workloads operate in a fully compliant environment

  @architecture_ga
  Scenario: Verify GCA API enablement and General Availability status
    Given the GCP project ID is configured
    When I evaluate compliance for "General Availability Service Status"
    And I check the status of the "cloudaicompanion.googleapis.com" API
    Then the API state must be "ENABLED"
    And all enabled GCA APIs must have at least one General Availability version

  @encryption_in_transit
  Scenario: Verify GCA API transport security and HTTPS TLS 1.2+ enforcement
    Given the GCP project ID is configured
    When I evaluate compliance for "Data in Transit Encryption Enforcement"
    Then the GCA API endpoint "cloudaicompanion.googleapis.com" must enforce HTTPS
    And legacy TLS versions (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) must be rejected

  @iam_least_privilege
  Scenario: Audit live GCA IAM policy bindings for least privilege
    Given the GCP project ID is configured
    When I evaluate compliance for "IAM Least Privilege Access Restriction"
    Then GCA service account bindings must explicitly enumerate permissions
    And no wildcard permissions or wildcard roles must be granted to GCA identities

  @network_boundary_security
  Scenario: Verify GCA network exposure prevention and perimeter controls
    Given the GCP project ID is configured
    When I evaluate compliance for "Network Boundary Security Exposure Prevention"
    Then GCA endpoints and associated resources must operate without public IP exposure
    And VPC boundary security controls must be active
