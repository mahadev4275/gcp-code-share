@opa @encryption_in_transit
Feature: [E2E Suite] Encryption in Transit & Protocol Compliance
  As a GCP Security Administrator
  I want to ensure all data in transit across external, internal, and database communication channels is encrypted
  So that legacy unencrypted protocols are rejected, insecure URL schemes are prohibited, and compliance with security standards is maintained

  Scenario: Service enforces TLS 1.2 or higher
    Given the GCP project ID is configured
    When the encryption-in-transit configuration is inspected
    Then HTTPS or TLS must be in use
    And TLS version must be 1.2 or higher
    And legacy protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) must be disabled

  Scenario: Internal communication uses TLS or mTLS
    Given a service transmits data to another service
    When the communication channel is validated
    Then data transmission must use TLS or mTLS
    And unencrypted traffic must be blocked
    And encryption events must be captured in audit logs

  Scenario: Load Balancer enforces modern TLS configuration
    Given a Load Balancer or API Gateway exists
    When the SSL/TLS policy configuration is inspected
    Then the SSL policy profile must be set to MODERN or RESTRICTED
    And the minimum TLS version must be TLS 1.2
    And legacy cipher suites must be explicitly disabled

  Scenario: Database requires TLS for all connections
    Given a managed database instance exists
    When the database SSL/TLS configuration is inspected
    Then SSL/TLS must be required for all client connections
    And connections without valid TLS certificates must be rejected
    And the minimum TLS version must be 1.2

  Scenario: No resource URLs use insecure communication schemes
    Given Terraform plan resource configurations are evaluated
    When resource attributes and URLs are inspected
    Then insecure URL schemes (http, ws, ftp, telnet) must not appear in any resource URLs

  Scenario: Observability API rejects insecure http scheme and mandates TLS 1.2 or higher
    Given the GCP project ID is configured
    When an API request is sent to the Observability API using an unsafe http scheme
    Then the request must be rejected by the server
    And live Observability API endpoints must mandate TLS version 1.2 or higher
