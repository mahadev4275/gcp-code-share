@encryption_in_transit
Feature: Encryption in Transit Enforcement
  As a GCP Security Administrator
  I want to ensure all data in transit across external, internal, and database communication channels is encrypted
  So that legacy unencrypted protocols are rejected and compliance with security standards is maintained

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
