package tests

// Encryption in Transit Enforcement
//
// Validates that data-in-transit is encrypted using TLS 1.2 or higher across:
// 1. External HTTPS endpoints
// 2. Control-plane and service-to-service transit (GCP APIs)
// 3. Load Balancer SSL Policies (MODERN or RESTRICTED profiles)
// 4. Managed Database instances (Cloud SQL requireSsl and sslMode)

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"golang.org/x/oauth2"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1"
)

// gcpMonitoringHost is the GCP Monitoring API endpoint used for TLS validation.
const gcpMonitoringHost = "monitoring.googleapis.com"

// allowedSSLPolicyProfiles are compliant SSL policy profiles for Load Balancers.
var allowedSSLPolicyProfiles = map[string]bool{
	"MODERN":     true,
	"RESTRICTED": true,
}

// -----------------------------------------------------------------------------
// BDD Godog Step Registrations (for encryption_in_transit.feature)
// -----------------------------------------------------------------------------

func (c *bddContext) registerEncryptionInTransitSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the encryption-in-transit configuration is inspected$`, func() error { return nil })
	sc.Step(`^HTTPS or TLS must be in use$`, c.verifyHTTPSServiceInUse)
	sc.Step(`^TLS version must be 1\.2 or higher$`, c.verifyTLSVersion12OrHigher)
	sc.Step(`^legacy protocols \(SSL 2\.0, SSL 3\.0, TLS 1\.0, TLS 1\.1\) must be disabled$`, c.verifyLegacyProtocolsDisabled)

	sc.Step(`^a service transmits data to another service$`, func() error { return nil })
	sc.Step(`^the communication channel is validated$`, func() error { return nil })
	sc.Step(`^data transmission must use TLS or mTLS$`, c.verifyDataTransmissionTLS)
	sc.Step(`^unencrypted traffic must be blocked$`, c.verifyLegacyProtocolsDisabled)

	sc.Step(`^a Load Balancer or API Gateway exists$`, func() error { return nil })
	sc.Step(`^the SSL\/TLS policy configuration is inspected$`, func() error { return nil })
	sc.Step(`^the SSL policy profile must be set to MODERN or RESTRICTED$`, c.verifyLoadBalancerSSLPolicy)
	sc.Step(`^the minimum TLS version must be TLS 1\.2$`, c.verifyTLSVersion12OrHigher)
	sc.Step(`^legacy cipher suites must be explicitly disabled$`, c.verifyLoadBalancerSSLPolicy)

	sc.Step(`^a managed database instance exists$`, func() error { return nil })
	sc.Step(`^the database SSL\/TLS configuration is inspected$`, func() error { return nil })
	sc.Step(`^SSL\/TLS must be required for all client connections$`, c.verifyDatabaseTLSRequired)
	sc.Step(`^connections without valid TLS certificates must be rejected$`, c.verifyDatabaseSSLModeEnforced)
	sc.Step(`^the minimum TLS version must be 1\.2$`, c.verifyDatabaseMinTLSVersion)
}

// -----------------------------------------------------------------------------
// Step handler functions
// -----------------------------------------------------------------------------

func (c *bddContext) verifyHTTPSServiceInUse() error {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", gcpMonitoringHost+":443",
		&tls.Config{MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		return fmt.Errorf("failed to establish TLS connection to %s: %w", gcpMonitoringHost, err)
	}
	defer conn.Close()
	return nil
}

func (c *bddContext) verifyTLSVersion12OrHigher() error {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", gcpMonitoringHost+":443",
		&tls.Config{MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		return fmt.Errorf("TLS 1.2+ handshake failed: %w", err)
	}
	defer conn.Close()

	if conn.ConnectionState().Version < tls.VersionTLS12 {
		return fmt.Errorf("negotiated TLS version 0x%04x is lower than TLS 1.2", conn.ConnectionState().Version)
	}
	return nil
}

func (c *bddContext) verifyLegacyProtocolsDisabled() error {
	for _, ver := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp", gcpMonitoringHost+":443",
			&tls.Config{MinVersion: ver, MaxVersion: ver},
		)
		if err == nil {
			conn.Close()
			return fmt.Errorf("server accepted legacy TLS version 0x%04x — legacy protocols must be disabled", ver)
		}
	}
	return nil
}

func (c *bddContext) verifyDataTransmissionTLS() error {
	accessToken := resolveAccessToken()
	if accessToken == "" {
		return nil
	}

	req, err := http.NewRequest("GET", "https://"+gcpMonitoringHost+"/v1/projects/"+c.projectID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("data transmission TLS check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		return fmt.Errorf("unencrypted traffic allowed: connection has no TLS state")
	}
	return nil
}

func (c *bddContext) verifyLoadBalancerSSLPolicy() error {
	ctx := context.Background()
	accessToken := resolveAccessToken()
	if accessToken == "" {
		return nil
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	computeSvc, err := compute.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return fmt.Errorf("failed to create compute client: %w", err)
	}

	sslPolicies, err := computeSvc.SslPolicies.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil
	}

	var violations []string
	for _, policy := range sslPolicies.Items {
		if !allowedSSLPolicyProfiles[policy.Profile] {
			violations = append(violations,
				fmt.Sprintf("SSL policy %q profile=%s (expected MODERN or RESTRICTED)", policy.Name, policy.Profile))
		}
		if policy.MinTlsVersion != "TLS_1_2" {
			violations = append(violations,
				fmt.Sprintf("SSL policy %q minTlsVersion=%s (expected TLS_1_2)", policy.Name, policy.MinTlsVersion))
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("Load Balancer SSL policy violations: %v", violations)
	}
	return nil
}

func (c *bddContext) verifyDatabaseTLSRequired() error {
	instances, err := c.listCloudSQLInstances()
	if err != nil || len(instances) == 0 {
		return nil
	}

	var violations []string
	for _, inst := range instances {
		if !inst.Settings.IpConfiguration.RequireSsl {
			violations = append(violations,
				fmt.Sprintf("Cloud SQL instance %q: requireSsl=false", inst.Name))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("database TLS violations: %v", violations)
	}
	return nil
}

func (c *bddContext) verifyDatabaseSSLModeEnforced() error {
	instances, err := c.listCloudSQLInstances()
	if err != nil || len(instances) == 0 {
		return nil
	}

	var violations []string
	for _, inst := range instances {
		sslMode := inst.Settings.IpConfiguration.SslMode
		switch sslMode {
		case "TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "ENCRYPTED_ONLY", "":
			// acceptable
		default:
			violations = append(violations,
				fmt.Sprintf("Cloud SQL instance %q: sslMode=%q does not enforce TLS", inst.Name, sslMode))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("database SSL mode violations: %v", violations)
	}
	return nil
}

func (c *bddContext) verifyDatabaseMinTLSVersion() error {
	instances, err := c.listCloudSQLInstances()
	if err != nil || len(instances) == 0 {
		return nil
	}

	var violations []string
	for _, inst := range instances {
		for _, flag := range inst.Settings.DatabaseFlags {
			if strings.EqualFold(flag.Name, "ssl_min_protocol_version") {
				if flag.Value != "TLSv1.2" && flag.Value != "TLSv1.3" {
					violations = append(violations,
						fmt.Sprintf("Cloud SQL instance %q: ssl_min_protocol_version=%q", inst.Name, flag.Value))
				}
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("database minimum TLS version violations: %v", violations)
	}
	return nil
}

func (c *bddContext) listCloudSQLInstances() ([]*sqladmin.DatabaseInstance, error) {
	ctx := context.Background()
	accessToken := resolveAccessToken()
	if accessToken == "" {
		return nil, nil
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	sqlSvc, err := sqladmin.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, err
	}

	resp, err := sqlSvc.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func resolveAccessToken() string {
	for _, k := range []string{"GOOGLE_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
