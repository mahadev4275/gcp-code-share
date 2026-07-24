package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/shell"
	"github.com/gruntwork-io/terratest/modules/terraform"
)

type PlanResourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Change  struct {
		Actions []string               `json:"actions"`
		Before  map[string]interface{} `json:"before"`
		After   map[string]interface{} `json:"after"`
	} `json:"change"`
}

type PlanJSON struct {
	ResourceChanges []PlanResourceChange `json:"resource_changes"`
}

func getModuleDir() string {
	return ".."
}

func generateModulePlanJSON(t *testing.T) (string, []PlanResourceChange, error) {
	dir := getModuleDir()
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" {
		projectID = "test-project-id"
	}

	tfOpts := &terraform.Options{
		TerraformDir: dir,
		Vars: map[string]interface{}{
			"project_id": projectID,
			"dataset_id": "test_logs",
			"sink_name":  "test_sink",
		},
		Logger: logger.Discard,
	}

	_, err := terraform.InitE(t, tfOpts)
	if err != nil {
		return "", nil, fmt.Errorf("failed to init terraform in %s: %w", dir, err)
	}

	planFile := "tfplan.binary"
	args := []string{"plan", "-out=" + planFile}
	for k, v := range tfOpts.Vars {
		args = append(args, fmt.Sprintf("-var=%s=%v", k, v))
	}
	_, err = terraform.RunTerraformCommandE(t, tfOpts, args...)
	if err != nil {
		return "", nil, fmt.Errorf("failed to plan terraform in %s: %w", dir, err)
	}
	defer os.Remove(filepath.Join(dir, planFile))

	planJSONStr, err := terraform.RunTerraformCommandE(t, tfOpts, "show", "-json", planFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to show plan json in %s: %w", dir, err)
	}

	var plan PlanJSON
	if err := json.Unmarshal([]byte(planJSONStr), &plan); err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal plan JSON: %w", err)
	}

	return planJSONStr, plan.ResourceChanges, nil
}

func runConftestAgainstModule(t *testing.T) error {
	planJSONStr, _, err := generateModulePlanJSON(t)
	if err != nil {
		return err
	}

	tmpJSONPath := filepath.Join(".", "tfplan.json")
	if err := os.WriteFile(tmpJSONPath, []byte(planJSONStr), 0644); err != nil {
		return fmt.Errorf("failed to write tfplan.json: %w", err)
	}
	defer os.Remove(tmpJSONPath)

	ctx := context.Background()
	conftestCmd := shell.Command{
		Command:    "conftest",
		Args:       []string{"test", "tfplan.json", "--policy", "./policies"},
		WorkingDir: ".",
		Logger:     logger.Discard,
	}

	output, err := shell.RunCommandContextAndGetOutputE(t, ctx, &conftestCmd)
	if err != nil {
		return fmt.Errorf("OPA Conftest policy violation for module:\n%s", output)
	}
	return nil
}
