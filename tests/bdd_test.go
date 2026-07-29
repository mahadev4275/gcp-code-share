package tests

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cucumber/godog"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/terraform"
)

var (
	godogTags         = flag.String("godog.tags", "", "filter scenarios by tags")
	tfQuietFlag       = flag.Bool("tf.quiet", true, "suppress verbose Terraform CLI output (default true; set -tf.quiet=false to view Terraform logs)")
	liveInfraOnce     sync.Once
	liveModuleOptsMap = make(map[string]*terraform.Options)
	liveModuleOpts    []*terraform.Options
	liveInfraSetupErr error
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


var (
	masterOpts *terraform.Options
)

// ensureLiveInfraProvisioned provisions the master composition module ONCE per test run using Terraform's DAG
func ensureLiveInfraProvisioned(t *testing.T) error {
	liveInfraOnce.Do(func() {
		projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			projectID = os.Getenv("PROJECT_ID")
		}
		if projectID == "" {
			liveInfraSetupErr = fmt.Errorf("GCP Project ID must be set via GOOGLE_CLOUD_PROJECT or PROJECT_ID environment variable for @live tests")
			return
		}

		region := os.Getenv("GOOGLE_CLOUD_REGION")
		if region == "" {
			region = "us-central1"
		}

		runnerDir, err := generateAmalgamatedComposition("..")
		if err != nil {
			liveInfraSetupErr = fmt.Errorf("failed to generate master composition module: %w", err)
			return
		}

		opts := &terraform.Options{
			TerraformDir: runnerDir,
			Vars: map[string]interface{}{
				"project_id": projectID,
				"project":    projectID,
				"projects":   []string{projectID},
				"region":     region,
				"location":   "global",
			},
			EnvVars: map[string]string{
				"GOOGLE_CLOUD_PROJECT":  projectID,
				"GOOGLE_PROJECT":        projectID,
				"GCP_PROJECT":           projectID,
				"CLOUDSDK_CORE_PROJECT": projectID,
			},
		}
		if isTFQuiet() {
			opts.Logger = logger.Discard
		}

		masterOpts = opts

		t.Log(">>> [ONE-TIME SETUP] Provisioning live infrastructure via master composition module using Terraform's dependency graph...")
		if _, err := terraform.InitAndApplyE(t, opts); err != nil {
			liveInfraSetupErr = fmt.Errorf("failed to init and apply master composition module: %w", err)
			return
		}
	})
	return liveInfraSetupErr
}

// teardownLiveInfra destroys all provisioned live infrastructure via the master composition module
func teardownLiveInfra(t *testing.T) {
	if masterOpts == nil {
		return
	}
	t.Log(">>> [ONE-TIME TEARDOWN] Destroying master composition live infrastructure...")
	if _, err := terraform.DestroyE(t, masterOpts); err != nil {
		t.Logf("warning: teardown destroy encountered error: %v", err)
	}
	cleanStaleStateFiles([]string{masterOpts.TerraformDir})
	masterOpts = nil
}

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

func TestE2ESuiteFeatures(t *testing.T) {
	// Guarantee single teardown execution at completion of TestE2ESuiteFeatures
	defer teardownLiveInfra(t)

	// Ensure suite_runner master composition module directory exists
	_, _ = generateAmalgamatedComposition("..")

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

				if masterOpts != nil {
					c.tfOpts = masterOpts
				} else {
					runnerDir := filepath.Join(".", "suite_runner")
					c.tfOpts = &terraform.Options{
						TerraformDir: runnerDir,
						Vars: map[string]interface{}{
							"project_id": projectID,
							"project":    projectID,
							"projects":   []string{projectID},
							"region":     region,
							"location":   "global",
						},
						EnvVars: map[string]string{
							"GOOGLE_CLOUD_PROJECT":  projectID,
							"GOOGLE_PROJECT":        projectID,
							"GCP_PROJECT":           projectID,
							"CLOUDSDK_CORE_PROJECT": projectID,
						},
					}
					if isTFQuiet() {
						c.tfOpts.Logger = logger.Discard
					}
				}

				// Always populate plannedChanges for policy/attribute inspections via sync.Once cached plan helper
				if len(c.plannedChanges) == 0 {
					if changes, err := getRepositoryPlanChanges(t); err == nil {
						c.plannedChanges = changes
					}
				}

				// LAZY SETUP: Only provision live infrastructure ONCE if scenario is tagged @live
				// GCA tests are API-only and do not require Terraform infrastructure
				if hasTag(scenario, "@live") && !hasTag(scenario, "@gca") {
					if err := ensureLiveInfraProvisioned(t); err != nil {
						return ctx, fmt.Errorf("failed live infrastructure provision step: %w", err)
					}
					c.allModuleTfOpts = liveModuleOpts
					if opt, ok := liveModuleOptsMap["../Trace_scope"]; ok {
						c.tfOpts = opt
					}
				}

				return ctx, nil
			})

			sc.After(func(ctx context.Context, scenario *godog.Scenario, err error) (context.Context, error) {
				// Teardown is handled cleanly via defer teardownLiveInfra(t)
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
