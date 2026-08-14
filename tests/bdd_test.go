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

var (
	godogTags     = flag.String("godog.tags", "", "filter scenarios by tags")
	tfQuietFlag   = flag.Bool("tf.quiet", true, "suppress verbose Terraform CLI output (default true; set -tf.quiet=false to view Terraform logs)")
	tfModulesFlag = flag.String("tf.modules", "", "comma-separated list of Terraform module directories to plan against (e.g. terraform-cmek-policy,Trace_scope)")
)

func isTFQuiet() bool {
	if v := os.Getenv("TF_QUIET"); v != "" {
		return v != "false" && v != "0"
	}
	if tfQuietFlag != nil {
		return *tfQuietFlag
	}
	return true
}

func cleanStaleStateFiles(dirs []string) {
	for _, dir := range dirs {
		_ = os.Remove(filepath.Join(dir, "terraform.tfstate"))
		_ = os.Remove(filepath.Join(dir, "terraform.tfstate.backup"))
		_ = os.Remove(filepath.Join(dir, ".terraform.tfstate.lock.info"))
	}
}

// bddContext holds the shared state for a single BDD scenario execution
type bddContext struct {
	projectID             string
	enabledServices       []string
	serviceNameToVersions map[string][]string
	traceServiceState     string
	currentAPI            string
	currentAPIState       string
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

func TestE2ESuiteFeatures(t *testing.T) {
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
			c.registerGCASteps(sc)
			c.registerSEC010GCASteps(sc)

			// Register lifecycle hooks
			sc.Before(func(ctx context.Context, scenario *godog.Scenario) (context.Context, error) {
				projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
				if projectID == "" {
					projectID = os.Getenv("PROJECT_ID")
				}
				c.projectID = projectID

				// Populate plannedChanges for policy/attribute inspections via cached plan helper.
				// When -tf.modules is specified, only those modules are included in the plan.
				if len(c.plannedChanges) == 0 {
					if changes, err := getRepositoryPlanChanges(t); err == nil {
						c.plannedChanges = changes
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
