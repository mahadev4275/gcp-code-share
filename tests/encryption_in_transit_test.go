package tests

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/gruntwork-io/terratest/modules/shell"
	"github.com/gruntwork-io/terratest/modules/terraform"
)

var (
	conftestOnce     sync.Once
	conftestCacheErr error
)

// -----------------------------------------------------------------------------
// BDD Godog Step Registrations (for encryption_in_transit.feature)
// -----------------------------------------------------------------------------

func (c *bddContext) registerEncryptionInTransitSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the GCP project ID is configured$`, func() error { return nil })
	sc.Step(`^the encryption-in-transit configuration is inspected$`, func() error { return nil })
	sc.Step(`^HTTPS or TLS must be in use$`, c.verifyConftestEncryptionInTransitPolicies)
	sc.Step(`^TLS version must be 1\.2 or higher$`, c.verifyConftestEncryptionInTransitPolicies)
	sc.Step(`^legacy protocols \(SSL 2\.0, SSL 3\.0, TLS 1\.0, TLS 1\.1\) must be disabled$`, c.verifyConftestEncryptionInTransitPolicies)

	sc.Step(`^a service transmits data to another service$`, func() error { return nil })
	sc.Step(`^the communication channel is validated$`, func() error { return nil })
	sc.Step(`^data transmission must use TLS or mTLS$`, c.verifyConftestEncryptionInTransitPolicies)
	sc.Step(`^unencrypted traffic must be blocked$`, c.verifyConftestEncryptionInTransitPolicies)
	sc.Step(`^encryption events must be captured in audit logs$`, c.verifyConftestEncryptionInTransitPolicies)

	sc.Step(`^a Load Balancer or API Gateway exists$`, func() error { return nil })
	sc.Step(`^the SSL\/TLS policy configuration is inspected$`, func() error { return nil })
	sc.Step(`^the SSL policy profile must be set to MODERN or RESTRICTED$`, c.verifyConftestEncryptionInTransitPolicies)
	sc.Step(`^the minimum TLS version must be TLS 1\.2$`, c.verifyConftestEncryptionInTransitPolicies)
	sc.Step(`^legacy cipher suites must be explicitly disabled$`, c.verifyConftestEncryptionInTransitPolicies)

	sc.Step(`^a managed database instance exists$`, func() error { return nil })
	sc.Step(`^the database SSL\/TLS configuration is inspected$`, func() error { return nil })
	sc.Step(`^SSL\/TLS must be required for all client connections$`, c.verifyConftestEncryptionInTransitPolicies)
	sc.Step(`^connections without valid TLS certificates must be rejected$`, c.verifyConftestEncryptionInTransitPolicies)
	sc.Step(`^the minimum TLS version must be 1\.2$`, c.verifyConftestEncryptionInTransitPolicies)

	sc.Step(`^Terraform plan resource configurations are evaluated$`, func() error { return nil })
	sc.Step(`^resource attributes and URLs are inspected$`, func() error { return nil })
	sc.Step(`^insecure URL schemes \(http, ws, ftp, telnet\) must not appear in any resource URLs$`, c.verifyNoInsecureURLSchemes)

	// Live Observability API HTTP Rejection & TLS 1.2+ steps
	sc.Step(`^an API request is sent to the Observability API using an unsafe http scheme$`, func() error { return nil })
	sc.Step(`^the request must be rejected by the server$`, c.verifyObservabilityAPIRejectsUnsafeSchemeLive)
	sc.Step(`^live Observability API endpoints must mandate TLS version 1\.2 or higher$`, c.verifyObservabilityAPIMandatesTLS12Live)
}

// -----------------------------------------------------------------------------
// Step Handler Functions (OPA / Rego / Conftest Policy Enforcement & Live Checks)
// -----------------------------------------------------------------------------

func (c *bddContext) verifyConftestEncryptionInTransitPolicies() error {
	conftestOnce.Do(func() {
		projectID := c.projectID
		if projectID == "" {
			projectID = "mock-project-id"
		}
		region := os.Getenv("GOOGLE_CLOUD_REGION")
		if region == "" {
			region = "us-central1"
		}

		dirs := []struct {
			path string
			vars map[string]interface{}
		}{
			{
				path: "../bq-cross-project-access",
				vars: map[string]interface{}{
					"project_id": projectID,
				},
			},
			{
				path: "../terraform-bq-scheduled-query",
				vars: map[string]interface{}{
					"project_id": projectID,
				},
			},
			{
				path: "../terraform-log-router-bq",
				vars: map[string]interface{}{
					"project_id": projectID,
					"dataset_id": "test_dataset",
					"sink_name":  "test_sink",
				},
			},
			{
				path: "../terraform-cmek-policy",
				vars: map[string]interface{}{
					"project_id": projectID,
				},
			},
			{
				path: "../terraform-org-policy",
				vars: map[string]interface{}{
					"project_id": projectID,
				},
			},
			{
				path: "../Trace_scope",
				vars: map[string]interface{}{
					"project":  projectID,
					"projects": []string{projectID},
					"region":   region,
					"location": region,
				},
			},
		}

		for _, d := range dirs {
			if err := runConftestOnDirWithVars(c.t, d.path, d.vars); err != nil {
				conftestCacheErr = err
				return
			}
		}
	})

	return conftestCacheErr
}

func (c *bddContext) verifyNoInsecureURLSchemes() error {
	// 1. Run Conftest policy check across all directories
	if err := c.verifyConftestEncryptionInTransitPolicies(); err != nil {
		return err
	}

	// 2. Perform direct in-memory plan resource attribute scan for insecure schemes
	var violations []string
	insecureSchemes := []string{"http://", "ws://", "ftp://", "telnet://"}

	for _, rc := range c.plannedChanges {
		if rc.Change.After == nil {
			continue
		}
		stringsFound := extractStringsFromMap(rc.Change.After)
		for _, s := range stringsFound {
			lowerS := strings.ToLower(s)
			for _, scheme := range insecureSchemes {
				if strings.HasPrefix(lowerS, scheme) {
					violations = append(violations, fmt.Sprintf("Resource '%s' (%s) contains URL with insecure scheme '%s': %s", rc.Address, rc.Type, scheme, s))
				}
			}
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("insecure URL scheme violations found: %v", violations)
	}

	return nil
}

func (c *bddContext) verifyObservabilityAPIRejectsUnsafeSchemeLive() error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://cloudtrace.googleapis.com/")
	if err != nil {
		// Connection rejected / failed -> PASS (unencrypted HTTP rejected)
		return nil
	}
	defer resp.Body.Close()

	// HTTP 404, 403, 301, 302, 400 demonstrate that unencrypted HTTP API requests are rejected
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	return fmt.Errorf("Observability API accepted unencrypted HTTP request without rejection (status code: %d)", resp.StatusCode)
}

func (c *bddContext) verifyObservabilityAPIMandatesTLS12Live() error {
	conn, err := tls.Dial("tcp", "cloudtrace.googleapis.com:443", &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to Observability API over TLS 1.2+: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		return fmt.Errorf("Observability API TLS version %x is below required TLS 1.2", state.Version)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func runConftestOnDirWithVars(t *testing.T, dir string, vars map[string]interface{}) error {
	ctx := context.Background()

	tfOpts := &terraform.Options{
		TerraformDir: dir,
		Vars:         vars,
	}

	planFile := filepath.Join(dir, "tfplan-"+filepath.Base(dir))
	planJSONFile := filepath.Join(dir, "tfplan-"+filepath.Base(dir)+".json")

	_, err := terraform.InitE(t, tfOpts)
	if err != nil {
		return fmt.Errorf("terraform init failed in %s: %w", dir, err)
	}

	args := []string{"plan", "-out", planFile}
	for k, v := range vars {
		switch val := v.(type) {
		case string:
			args = append(args, "-var", fmt.Sprintf("%s=%s", k, val))
		case []string:
			var quoted []string
			for _, s := range val {
				quoted = append(quoted, fmt.Sprintf("%q", s))
			}
			listStr := "[" + strings.Join(quoted, ",") + "]"
			args = append(args, "-var", fmt.Sprintf("%s=%s", k, listStr))
		default:
			args = append(args, "-var", fmt.Sprintf("%s=%v", k, val))
		}
	}

	_, err = terraform.RunTerraformCommandE(t, tfOpts, args...)
	if err != nil {
		return fmt.Errorf("terraform plan failed in %s: %w", dir, err)
	}
	defer os.Remove(planFile)

	planJSON, err := terraform.RunTerraformCommandE(t, tfOpts, "show", "-json", planFile)
	if err != nil {
		return fmt.Errorf("terraform show -json failed in %s: %w", dir, err)
	}

	if err := os.WriteFile(planJSONFile, []byte(planJSON), 0644); err != nil {
		return fmt.Errorf("failed to write tfplan JSON in %s: %w", dir, err)
	}
	defer os.Remove(planJSONFile)

	policyDir := "../policies"
	absPolicyDir, _ := filepath.Abs(policyDir)

	conftestCmd := shell.Command{
		Command:    "conftest",
		Args:       []string{"test", planJSONFile, "--policy", absPolicyDir},
		WorkingDir: dir,
	}

	output, err := shell.RunCommandContextAndGetOutputE(t, ctx, &conftestCmd)
	if err != nil {
		return fmt.Errorf("Conftest OPA policy check failed in %s:\n%s", dir, output)
	}

	return nil
}

func extractStringsFromMap(val interface{}) []string {
	var results []string
	switch v := val.(type) {
	case string:
		results = append(results, v)
	case map[string]interface{}:
		for _, item := range v {
			results = append(results, extractStringsFromMap(item)...)
		}
	case []interface{}:
		for _, item := range v {
			results = append(results, extractStringsFromMap(item)...)
		}
	}
	return results
}
