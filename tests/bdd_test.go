package tests

import (
	"context"
	"flag"
	"fmt"
	"os"
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
	allModuleTfOpts       []*terraform.Options
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

func hasTag(scenario *godog.Scenario, tag string) bool {
	for _, t := range scenario.Tags {
		if t.Name == tag {
			return true
		}
	}
	return false
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
			c.registerEncryptionComplianceSteps(sc)

			// Register Terratest lifecycle hooks
			sc.Before(func(ctx context.Context, scenario *godog.Scenario) (context.Context, error) {
				projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
				if projectID == "" {
					projectID = os.Getenv("PROJECT_ID")
				}
				c.projectID = projectID

				region := os.Getenv("GOOGLE_CLOUD_REGION")
				if region == "" {
					region = "us-central1"
				}

				c.tfOpts = &terraform.Options{
					TerraformDir: "../Trace_scope",
					Vars: map[string]interface{}{
						"project":  projectID,
						"region":   region,
						"location": region,
						"projects": []string{projectID},
					},
				}

				// Always populate plannedChanges for policy and attribute inspections
				if len(c.plannedChanges) == 0 {
					if changes, err := getRepositoryPlanChanges(t); err == nil {
						c.plannedChanges = changes
					}
				}

				return ctx, nil
			})

			sc.After(func(ctx context.Context, scenario *godog.Scenario, err error) (context.Context, error) {
				if hasTag(scenario, "@live") && len(c.allModuleTfOpts) > 0 {
					// LIVE INFRASTRUCTURE SUITE TEARDOWN: Destroy live GCP resources if created
					for i := len(c.allModuleTfOpts) - 1; i >= 0; i-- {
						terraform.Destroy(t, c.allModuleTfOpts[i])
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
