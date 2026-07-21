package tests

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cucumber/godog"
	"github.com/gruntwork-io/terratest/modules/terraform"
)

var godogTags = flag.String("godog.tags", "", "filter scenarios by tags")

// bddContext holds the shared state for a single BDD scenario execution
type bddContext struct {
	projectID             string
	enabledServices       []string
	serviceNameToVersions map[string][]string
	traceServiceState     string
	tfOpts                *terraform.Options
	t                     *testing.T
	plannedChanges        []PlanResourceChange
}

func (c *bddContext) theGCPProjectIDIsConfigured() error {
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" {
		return fmt.Errorf("GCP Project ID must be set via the GOOGLE_CLOUD_PROJECT or PROJECT_ID environment variable")
	}
	c.projectID = projectID
	return nil
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			c := &bddContext{t: t}

			// Common steps
			sc.Step(`^the GCP project ID is configured$`, c.theGCPProjectIDIsConfigured)

			// Delegate step registration to domain-specific files
			c.registerGAPISteps(sc)
			c.registerObservabilitySteps(sc)
			c.registerResourcePublicAccessSteps(sc)
			c.registerCMEKPolicySteps(sc)
			c.registerIAMPermissionRestrictionsSteps(sc)
			c.registerCustomRolesForControlPlaneSteps(sc)
			c.registerSegregationOfDutiesSteps(sc)
			c.registerEncryptionInTransitSteps(sc)

			// Register Terratest lifecycle hooks
			sc.Before(func(ctx context.Context, scenario *godog.Scenario) (context.Context, error) {
				// Populate project ID from environment
				projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
				if projectID == "" {
					projectID = os.Getenv("PROJECT_ID")
				}
				c.projectID = projectID

				// Setup target directory
				terraformDir := "../Trace_scope"
				c.tfOpts = &terraform.Options{
					TerraformDir: terraformDir,
				}

				// Check for TF_VAR_FILE
				tfVarFile := os.Getenv("TF_VAR_FILE")
				if tfVarFile != "" {
					c.tfOpts.VarFiles = []string{tfVarFile}
				} else {
					// Check for default tfvars files
					hasTfvars := false
					if _, err := os.Stat(filepath.Join(terraformDir, "terraform.tfvars")); err == nil {
						hasTfvars = true
					} else if _, err := os.Stat(filepath.Join(terraformDir, "terraform.tfvars.json")); err == nil {
						hasTfvars = true
					}

					// Fallback to env vars if no tfvars files
					if !hasTfvars {
						projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
						if projectID == "" {
							projectID = os.Getenv("PROJECT_ID")
						}
						region := os.Getenv("GOOGLE_CLOUD_REGION")
						if region == "" {
							region = "us-central1"
						}

						c.tfOpts.Vars = map[string]interface{}{
							"project":  projectID,
							"region":   region,
							"location": region,
							"projects": []string{projectID},
						}
					}
				}

				// Run Terraform Init and Apply
				t.Logf("Running terraform init and apply for scenario: %s", scenario.Name)
				if _, err := terraform.InitAndApplyContextE(t, ctx, c.tfOpts); err != nil {
					return ctx, fmt.Errorf("terraform apply failed: %w", err)
				}

				return ctx, nil
			})

			sc.After(func(ctx context.Context, scenario *godog.Scenario, err error) (context.Context, error) {
				// Run Terraform Destroy to clean up resources
				if c.tfOpts != nil {
					t.Logf("Running terraform destroy for scenario: %s", scenario.Name)
					if _, destErr := terraform.DestroyContextE(t, ctx, c.tfOpts); destErr != nil {
						t.Errorf("terraform destroy failed: %v", destErr)
					}
				}
				return ctx, nil
			})
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t,
			Tags:     *godogTags,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
