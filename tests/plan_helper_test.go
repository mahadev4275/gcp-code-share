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

	"github.com/gruntwork-io/terratest/modules/logger"
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
	if isTFQuiet() {
		tfOpts.Logger = logger.Discard
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

// discoverTerraformModuleDirs dynamically detects every subdirectory in root containing .tf files
func discoverTerraformModuleDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("failed to read root directory %s: %w", root, err)
	}

	var moduleDirs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "tests" || name == "policies" || name == "vendor" {
			continue
		}

		dirPath := filepath.Join(root, name)
		hasTF := false

		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(info.Name(), ".tf") {
				hasTF = true
				return filepath.SkipAll
			}
			return nil
		})
		if err != nil && err != filepath.SkipAll {
			return nil, err
		}

		if hasTF {
			moduleDirs = append(moduleDirs, dirPath)
		}
	}
	return moduleDirs, nil
}

// getDeclaredVariablesInDir parses root .tf files in dir for variable "name" definitions
func getDeclaredVariablesInDir(dir string) map[string]bool {
	declared := make(map[string]bool)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return declared
	}
	re := regexp.MustCompile(`variable\s+"([^"]+)"`)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		matches := re.FindAllStringSubmatch(string(content), -1)
		for _, m := range matches {
			if len(m) > 1 {
				declared[m[1]] = true
			}
		}
	}
	return declared
}

// buildVarsForModule filters variable assignments to ONLY include variables declared by the target module
func buildVarsForModule(dir, projectID, region string) map[string]interface{} {
	declared := getDeclaredVariablesInDir(dir)
	allPossible := map[string]interface{}{
		"project_id":     projectID,
		"project":        projectID,
		"projects":       []string{projectID},
		"region":         region,
		"location":       region,
		"dataset_id":     "test_dataset",
		"sink_name":      "test_sink",
		"bucket_id":      "test_bucket",
		"link_id":        "test_link",
		"retention_days": 30,
	}

	vars := make(map[string]interface{})
	for k, v := range allPossible {
		if declared[k] {
			vars[k] = v
		}
	}
	return vars
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

		dirs, err := discoverTerraformModuleDirs("..")
		if err != nil {
			cachedPlanErr = fmt.Errorf("failed to discover terraform modules: %w", err)
			return
		}

		var allChanges []PlanResourceChange
		for _, dir := range dirs {
			modVars := buildVarsForModule(dir, projectID, region)
			changes, err := getPlanResourceChanges(t, dir, modVars)
			if err != nil {
				cachedPlanErr = fmt.Errorf("failed to get plan changes for %s: %w", dir, err)
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
