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

	terraformDir := "../Trace_scope"

	// Dynamically retrieve GCP parameters from environment variables
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" {
		projectID = "mock-project-id" // Fallback for local static plan checking
	}

	region := os.Getenv("GOOGLE_CLOUD_REGION")
	if region == "" {
		region = "us-central1" // Fallback default
	}

	// Define Options
	terraformOptions := &terraform.Options{
		TerraformDir: terraformDir,
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

		// Fallback to env vars only if no tfvars files exist
		if !hasTfvars {
			terraformOptions.Vars = map[string]interface{}{
				"project":  projectID,
				"region":   region,
				"location": region,
				"projects": []string{projectID},
			}
		}
	}

	terraformOptions = terraform.WithDefaultRetryableErrors(t, terraformOptions)

	// Run terraform init and plan
	planFile := filepath.Join(terraformDir, "tfplan")
	ctx := context.Background()
	terraform.RunTerraformCommandContext(t, ctx, terraformOptions, "init")
	terraform.RunTerraformCommandContext(t, ctx, terraformOptions, "plan", "-out", planFile)

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
		Args:       []string{"test", tmpPlanJSON, "--policy", "../policies"},
		WorkingDir: terraformDir,
	}
	if isTFQuiet() {
		conftestCmd.Logger = logger.Discard
	}
	
	output, err := shell.RunCommandContextAndGetOutputE(t, ctx, &conftestCmd)
	assert.NoError(t, err, "Conftest policy check failed:\n%s", output)
}
