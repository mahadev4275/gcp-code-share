package tests

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/cucumber/godog"
	"github.com/gruntwork-io/terratest/modules/terraform"
)

var (
	godogTags         = flag.String("godog.tags", "", "filter scenarios by tags")
	liveInfraOnce     sync.Once
	liveModuleOptsMap = make(map[string]*terraform.Options)
	liveModuleOpts    []*terraform.Options
	liveInfraSetupErr error
)

// ensureLiveInfraProvisioned dynamically discovers and provisions all repository Terraform modules ONCE per test run
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

		dirs, err := discoverTerraformModuleDirs("..")
		if err != nil {
			liveInfraSetupErr = fmt.Errorf("failed to dynamically discover terraform module directories: %w", err)
			return
		}

		commonVars := map[string]interface{}{
			"project_id": projectID,
			"project":    projectID,
			"projects":   []string{projectID},
			"region":     region,
			"location":   region,
			"dataset_id": "test_dataset",
			"sink_name":  "test_sink",
		}

		t.Log(">>> [ONE-TIME SETUP] Provisioning live infrastructure across dynamically discovered Terraform modules...")
		for _, modPath := range dirs {
			opts := &terraform.Options{
				TerraformDir: modPath,
				Vars:         commonVars,
			}
			t.Logf(">>> Applying Terraform module: %s", modPath)
			if _, err := terraform.InitAndApplyE(t, opts); err != nil {
				liveInfraSetupErr = fmt.Errorf("failed to init and apply terraform module %s: %w", modPath, err)
				return
			}
			liveModuleOptsMap[modPath] = opts
			liveModuleOpts = append(liveModuleOpts, opts)
		}
	})
	return liveInfraSetupErr
}

// teardownLiveInfra destroys all provisioned live modules in reverse order ONCE per test run
func teardownLiveInfra(t *testing.T) {
	if len(liveModuleOpts) == 0 {
		return
	}
	t.Log(">>> [ONE-TIME TEARDOWN] Destroying all provisioned live infrastructure modules...")
	for i := len(liveModuleOpts) - 1; i >= 0; i-- {
		t.Logf(">>> Destroying Terraform module: %s", liveModuleOpts[i].TerraformDir)
		if _, err := terraform.DestroyE(t, liveModuleOpts[i]); err != nil {
			t.Errorf("failed to destroy terraform module %s: %v", liveModuleOpts[i].TerraformDir, err)
		}
	}
	liveModuleOpts = nil
	liveModuleOptsMap = make(map[string]*terraform.Options)
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

func TestFeatures(t *testing.T) {
	// Guarantee single teardown execution at completion of TestFeatures
	defer teardownLiveInfra(t)

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

				if opt, ok := liveModuleOptsMap["../Trace_scope"]; ok {
					c.tfOpts = opt
				} else {
					c.tfOpts = &terraform.Options{
						TerraformDir: "../Trace_scope",
						Vars: map[string]interface{}{
							"project":  projectID,
							"region":   region,
							"location": region,
							"projects": []string{projectID},
						},
					}
				}

				// Always populate plannedChanges for policy/attribute inspections via sync.Once cached plan helper
				if len(c.plannedChanges) == 0 {
					if changes, err := getRepositoryPlanChanges(t); err == nil {
						c.plannedChanges = changes
					}
				}

				// LAZY SETUP: Only provision live infrastructure ONCE if scenario is tagged @live
				if hasTag(scenario, "@live") {
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
