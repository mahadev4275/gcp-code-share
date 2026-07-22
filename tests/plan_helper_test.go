package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

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

var (
	repoPlanChangesOnce sync.Once
	cachedPlanChanges   []PlanResourceChange
	cachedPlanErr       error
)

func getPlanResourceChanges(t *testing.T, dir string, vars map[string]interface{}) ([]PlanResourceChange, error) {
	tfOpts := &terraform.Options{
		TerraformDir: dir,
		Vars:         vars,
	}

	planFile := filepath.Join(dir, "tfplan-"+filepath.Base(dir))

	_, err := terraform.InitE(t, tfOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to init in %s: %w", dir, err)
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
		return nil, fmt.Errorf("failed to plan in %s: %w", dir, err)
	}
	defer os.Remove(planFile)

	planJSONStr, err := terraform.RunTerraformCommandE(t, tfOpts, "show", "-json", planFile)
	if err != nil {
		return nil, fmt.Errorf("failed to show json in %s: %w", dir, err)
	}

	var plan PlanJSON
	if err := json.Unmarshal([]byte(planJSONStr), &plan); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plan JSON for %s: %w", dir, err)
	}

	return plan.ResourceChanges, nil
}

// getRepositoryPlanChanges runs terraform plan on all modules in the repository with sync.Once caching
func getRepositoryPlanChanges(t *testing.T) ([]PlanResourceChange, error) {
	repoPlanChangesOnce.Do(func() {
		projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			projectID = os.Getenv("PROJECT_ID")
		}
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

		var allChanges []PlanResourceChange
		for _, d := range dirs {
			changes, err := getPlanResourceChanges(t, d.path, d.vars)
			if err != nil {
				cachedPlanErr = fmt.Errorf("failed to get plan changes for %s: %w", d.path, err)
				return
			}
			allChanges = append(allChanges, changes...)
		}
		cachedPlanChanges = allChanges
	})

	return cachedPlanChanges, cachedPlanErr
}

func isIAMResource(resourceType string) bool {
	lowerType := strings.ToLower(resourceType)
	return strings.Contains(lowerType, "_iam_") && !strings.Contains(lowerType, "deny")
}

func getStringVal(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func getSliceOfStrings(m map[string]interface{}, key string) []string {
	var result []string
	if val, ok := m[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			for _, item := range slice {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
		}
	}
	return result
}

func extractEnvToken(value string) string {
	value = strings.ToLower(value)
	re := regexp.MustCompile(`(^|[-_.])(dev|qa|uat|nprd|se|prd|prod)($|[-_.])`)
	m := re.FindStringSubmatch(value)
	if len(m) < 3 {
		return ""
	}
	return m[2]
}
