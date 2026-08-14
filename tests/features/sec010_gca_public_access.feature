@sec010 @gca @public_access
Feature: SEC.010 - Gemini Cloud Assist & Gemini for Google Cloud API Public Access Prevention
  As a GCP Security Administrator
  I want to verify that Gemini Cloud Assist API and Gemini for Google Cloud API
  (cloudaicompanion.googleapis.com) are not publicly accessible
  So that Citi resources and data remain private and protected from public availability

  # =========================================================================
  # POSITIVE SCENARIOS – Verify secure baseline
  # =========================================================================

  @positive @iam
  Scenario: [Positive] Verify GCA API has no public IAM bindings
    Given the GCP project ID is configured
    When I audit the project IAM policy for Gemini Cloud Assist identities
    Then no GCA-related IAM binding should contain "allUsers" or "allAuthenticatedUsers"

  @positive @endpoint
  Scenario: [Positive] Verify GCA API endpoint is not publicly exposed
    Given the GCP project ID is configured
    When I resolve the DNS addresses for "cloudaicompanion.googleapis.com"
    Then the endpoint should route through Google-managed infrastructure only

  @positive @service_enabled
  Scenario: [Positive] Verify GCA API is enabled and restricted to the designated project
    Given the GCP project ID is configured
    When I check the enablement status of "cloudaicompanion.googleapis.com"
    Then the API must be enabled and bound to the designated project only

  # =========================================================================
  # NEGATIVE SCENARIOS – Verify guardrails reject violations
  # =========================================================================

  @negative @unauthenticated
  Scenario: [Negative] Unauthenticated request to GCA API must be rejected
    Given the GCP project ID is configured
    When I send an unauthenticated HTTP request to "cloudaicompanion.googleapis.com"
    Then the API must reject the request with HTTP 401 or 403

  @negative @public_member
  Scenario: [Negative] Public member binding on GCA project IAM must be detected
    Given the GCP project ID is configured
    When I simulate adding "allUsers" to a GCA-related role on the project
    Then the security control must flag the violation as non-compliant

  @negative @wildcard_role
  Scenario: [Negative] Wildcard or overprivileged role on GCA identity must be detected
    Given the GCP project ID is configured
    When I audit GCA identities for roles/owner or roles/editor bindings
    Then no GCA identity should hold overprivileged roles
