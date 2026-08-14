package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/shell"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestPublicAccessRegoPolicyWithTerratest(t *testing.T) {
	t.Parallel()

	// Dynamically retrieve GCP parameters from environment variables
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" {
		projectID = "mock-project-id" // Fallback for local static plan checking
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
				"project":            projectID,
				"monitored_projects": []string{projectID},
				"location":           "global",
			},
		},
	}

	allowedModules := getModuleFilter()
	var filteredDirs []struct {
		path string
		vars map[string]interface{}
	}

	if len(allowedModules) > 0 {
		allowedMap := make(map[string]bool)
		for _, m := range allowedModules {
			allowedMap[m] = true
		}
		for _, d := range dirs {
			if allowedMap[filepath.Base(d.path)] {
				filteredDirs = append(filteredDirs, d)
			}
		}
	} else {
		filteredDirs = dirs
	}

	for _, d := range filteredDirs {
		d := d // Capture loop variable for parallel execution
		t.Run(filepath.Base(d.path), func(t *testing.T) {
			t.Parallel()

			terraformDir := d.path
			planFile := filepath.Join(terraformDir, "tfplan")

			// Define Options with PlanFilePath so InitAndPlan formats -var flags correctly
			terraformOptions := &terraform.Options{
				TerraformDir: terraformDir,
				PlanFilePath: planFile,
			}
			if isTFQuiet() {
				terraformOptions.Logger = logger.Discard
			}

			// Use TF_VAR_FILE if specified
			tfVarFile := os.Getenv("TF_VAR_FILE")
			if tfVarFile != "" {
				terraformOptions.VarFiles = []string{tfVarFile}
			} else {
				// Detect default tfvars files in the Terraform directory
				hasTfvars := false
				if _, err := os.Stat(filepath.Join(terraformDir, "terraform.tfvars")); err == nil {
					hasTfvars = true
				} else if _, err := os.Stat(filepath.Join(terraformDir, "terraform.tfvars.json")); err == nil {
					hasTfvars = true
				} else if files, _ := filepath.Glob(filepath.Join(terraformDir, "*.auto.tfvars")); len(files) > 0 {
					hasTfvars = true
				} else if files, _ := filepath.Glob(filepath.Join(terraformDir, "*.auto.tfvars.json")); len(files) > 0 {
					hasTfvars = true
				}

				if !hasTfvars {
					terraformOptions.Vars = d.vars
				}
			}

			terraformOptions = terraform.WithDefaultRetryableErrors(t, terraformOptions)

			// Run terraform init and plan with formatted vars via PlanFilePath
			ctx := context.Background()
			terraform.InitAndPlan(t, terraformOptions)

			// Run terraform show -json tfplan
			planJSON := terraform.RunTerraformCommandContext(t, ctx, terraformOptions, "show", "-json", planFile)

			// Save plan JSON to a temporary file for conftest
			tmpPlanJSON := filepath.Join(terraformDir, "tfplan.json")
			err := os.WriteFile(tmpPlanJSON, []byte(planJSON), 0644)
			assert.NoError(t, err)
			defer os.Remove(tmpPlanJSON)
			defer os.Remove(planFile)

			// Execute conftest command
			conftestCmd := shell.Command{
				Command:    "conftest",
				Args:       []string{"test", "tfplan.json", "--policy", "../policies", "--namespace", "public_access"},
				WorkingDir: terraformDir,
			}
			if isTFQuiet() {
				conftestCmd.Logger = logger.Discard
			}
			
			output, err := shell.RunCommandContextAndGetOutputE(t, ctx, &conftestCmd)
			assert.NoError(t, err, "Conftest policy check failed in %s:\n%s", terraformDir, output)
		})
	}
}
