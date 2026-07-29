package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

var (
	repoPlanChangesOnce sync.Once
	cachedPlanChanges   []PlanResourceChange
	cachedPlanErr       error
)

func getPlanResourceChanges(t *testing.T, dir string, vars map[string]interface{}) ([]PlanResourceChange, error) {
	projectID, _ := vars["project_id"].(string)
	if projectID == "" {
		projectID, _ = vars["project"].(string)
	}

	tfOpts := &terraform.Options{
		TerraformDir: dir,
		Vars:         vars,
		VarFiles:     detectVarFiles(dir),
		EnvVars: map[string]string{
			"GOOGLE_CLOUD_PROJECT":  projectID,
			"GOOGLE_PROJECT":        projectID,
			"GCP_PROJECT":           projectID,
			"CLOUDSDK_CORE_PROJECT": projectID,
		},
	}
	if isTFQuiet() {
		tfOpts.Logger = logger.Discard
	}

	planFileName := "tfplan-" + filepath.Base(dir)
	planFile := filepath.Join(dir, planFileName)

	_, err := terraform.InitE(t, tfOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to init in %s: %w", dir, err)
	}

	args := []string{"plan", "-out", planFileName}
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

	planJSONStr, err := terraform.RunTerraformCommandE(t, tfOpts, "show", "-json", planFileName)
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
		if strings.HasPrefix(name, ".") || name == "tests" || name == "policies" || name == "vendor" || name == "tf_for_scope" {
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

// detectVarFiles checks for terraform.tfvars or *.auto.tfvars files in dir
func detectVarFiles(dir string) []string {
	var varFiles []string
	candidates := []string{"terraform.tfvars", "terraform.tfvars.json"}
	for _, c := range candidates {
		path := filepath.Join(dir, c)
		if _, err := os.Stat(path); err == nil {
			varFiles = append(varFiles, path)
		}
	}
	autoFiles, _ := filepath.Glob(filepath.Join(dir, "*.auto.tfvars"))
	varFiles = append(varFiles, autoFiles...)
	autoJSONFiles, _ := filepath.Glob(filepath.Join(dir, "*.auto.tfvars.json"))
	varFiles = append(varFiles, autoJSONFiles...)
	return varFiles
}



func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			if (strings.HasPrefix(info.Name(), ".") && info.Name() != ".") || info.Name() == "tests" {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

// generateAmalgamatedComposition creates a master composition Terraform module in tests/suite_runner/main.tf
func generateAmalgamatedComposition(root string) (string, error) {
	dirs, err := discoverTerraformModuleDirs(root)
	if err != nil {
		return "", err
	}
	runnerDir := filepath.Join(".", "suite_runner")
	// Clean stale Terraform state to avoid lock file conflicts with updated provider constraints
	_ = os.Remove(filepath.Join(runnerDir, ".terraform.lock.hcl"))
	_ = os.RemoveAll(filepath.Join(runnerDir, ".terraform"))
	modulesDir := filepath.Join(runnerDir, "modules")
	if err := os.MkdirAll(modulesDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create suite_runner/modules directory: %w", err)
	}

	// Copy each discovered module into tests/suite_runner/modules/
	for _, dir := range dirs {
		base := filepath.Base(dir)
		dstDir := filepath.Join(modulesDir, base)
		_ = os.RemoveAll(dstDir)
		if err := copyDir(dir, dstDir); err != nil {
			return "", fmt.Errorf("failed to copy module %s to %s: %w", base, dstDir, err)
		}
	}

	// Normalize Trace_scope provider version to be compatible with other modules' ~> 6.0 constraint,
	// and add google-beta provider required for google_observability_trace_scope resource.
	copiedTraceScopeProvider := filepath.Join(modulesDir, "Trace_scope", "provider.tf")
	_ = os.WriteFile(copiedTraceScopeProvider, []byte(`terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 6.0.0"
    }
  }
}
`), 0644)

	// Patch the nested tf_for_scope module to use google-beta provider for the trace scope resource
	copiedScopeTF := filepath.Join(modulesDir, "Trace_scope", "modules", "tf_for_scope", "main.tf")
	if content, err := os.ReadFile(copiedScopeTF); err == nil {
		contentStr := string(content)
		if !strings.Contains(contentStr, "provider = google-beta") {
			newContent := `terraform {
  required_providers {
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 6.0.0"
    }
  }
}

` + strings.Replace(contentStr,
				`resource "google_observability_trace_scope" "observability_trace_scope" {`,
				`resource "google_observability_trace_scope" "observability_trace_scope" {
  provider       = google-beta`, 1)
			_ = os.WriteFile(copiedScopeTF, []byte(newContent), 0644)
		}
	}

	// Patch Trace_scope/main.tf to pass the google-beta provider to the nested tf_for_scope module
	copiedTraceScopeMain := filepath.Join(modulesDir, "Trace_scope", "main.tf")
	if content, err := os.ReadFile(copiedTraceScopeMain); err == nil {
		contentStr := string(content)
		if !strings.Contains(contentStr, "providers") {
			newContent := strings.Replace(contentStr,
				`source = "./modules/tf_for_scope"`,
				`source = "./modules/tf_for_scope"

  providers = {
    google-beta = google-beta
  }`, 1)
			_ = os.WriteFile(copiedTraceScopeMain, []byte(newContent), 0644)
		}
	}

	// Add output.tf in copied Trace_scope inside suite_runner/modules/ to expose trace_scope_id from tf_for_scope
	copiedTraceScopeOutput := filepath.Join(modulesDir, "Trace_scope", "output.tf")
	_ = os.WriteFile(copiedTraceScopeOutput, []byte(`output "trace_scope_id" {
  value = module.trace_scope.trace_scope_id
}
`), 0644)

	// Patch copied logbucket-bqlink/main.tf inside suite_runner/modules/ to use _Default log bucket instead of _Trace
	copiedLogbucketTF := filepath.Join(modulesDir, "logbucket-bqlink", "main.tf")
	if content, err := os.ReadFile(copiedLogbucketTF); err == nil {
		contentStr := string(content)
		newContent := strings.Replace(contentStr, `bucket_id = "_Trace"`, `bucket_id = "_Default"`, 1)
		_ = os.WriteFile(copiedLogbucketTF, []byte(newContent), 0644)
	}

	var sb strings.Builder
	sb.WriteString(`# System-generated master composition module for BDD test execution
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 6.0.0"
    }
  }
}

provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

provider "google-beta" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

variable "project_id" {
  type = string
}
variable "project" {
  type = string
}
variable "projects" {
  type = list(string)
}
variable "region" {
  type    = string
  default = "us-central1"
}
variable "location" {
  type    = string
  default = "global"
}

`)

	for _, dir := range dirs {
		base := filepath.Base(dir)
		if base == "tf_for_scope" {
			continue // tf_for_scope is called from Trace_scope
		}
		modName := strings.ReplaceAll(base, "-", "_")
		declared := getDeclaredVariablesInDir(dir)

		relSource := "./modules/" + base
		sb.WriteString(fmt.Sprintf("module %q {\n", modName))
		sb.WriteString(fmt.Sprintf("  source = %q\n", relSource))

		if declared["project_id"] {
			switch base {
			case "logbucket-bqlink", "terraform-log-router-bq":
				sb.WriteString("  project_id = module.Trace_scope.trace_scope_id != \"\" ? var.project_id : var.project_id\n")
			case "bq-cross-project-access", "terraform-bq-scheduled-query":
				sb.WriteString("  project_id = module.terraform_log_router_bq.sink_name != \"\" ? var.project_id : var.project_id\n")
			default:
				sb.WriteString("  project_id = var.project_id\n")
			}
		}
		if declared["project"] {
			sb.WriteString("  project = var.project\n")
		}
		if declared["projects"] {
			sb.WriteString("  projects = var.projects\n")
		}
		if declared["monitored_projects"] {
			sb.WriteString("  monitored_projects = var.projects\n")
		}
		if declared["region"] {
			sb.WriteString("  region = var.region\n")
		}
		if declared["location"] {
			sb.WriteString("  location = var.location\n")
		}
		if declared["dataset_id"] {
			sb.WriteString("  dataset_id = \"trace_spans\"\n")
		}
		if declared["sink_name"] {
			sb.WriteString("  sink_name = \"test_sink\"\n")
		}

		sb.WriteString("}\n\n")
	}

	mainTFPath := filepath.Join(runnerDir, "main.tf")
	if err := os.WriteFile(mainTFPath, []byte(sb.String()), 0644); err != nil {
		return "", fmt.Errorf("failed to write master composition main.tf: %w", err)
	}

	return runnerDir, nil
}

// getRepositoryPlanChanges runs terraform plan on the master composition module with sync.Once caching
func getRepositoryPlanChanges(t *testing.T) ([]PlanResourceChange, error) {
	repoPlanChangesOnce.Do(func() {
		projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			projectID = os.Getenv("PROJECT_ID")
		}
		if projectID == "" {
			cachedPlanErr = fmt.Errorf("GCP Project ID must be set via GOOGLE_CLOUD_PROJECT or PROJECT_ID environment variable")
			return
		}

		region := os.Getenv("GOOGLE_CLOUD_REGION")
		if region == "" {
			region = "us-central1"
		}

		runnerDir, err := generateAmalgamatedComposition("..")
		if err != nil {
			cachedPlanErr = fmt.Errorf("failed to generate master composition module: %w", err)
			return
		}

		vars := map[string]interface{}{
			"project_id": projectID,
			"project":    projectID,
			"projects":   []string{projectID},
			"region":     region,
			"location":   "global",
		}

		changes, err := getPlanResourceChanges(t, runnerDir, vars)
		if err != nil {
			cachedPlanErr = fmt.Errorf("failed to get plan changes for master composition module: %w", err)
			return
		}
		cachedPlanChanges = changes
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

func (c *bddContext) runConftestAgainstMasterComposition() error {
	runnerDir, err := generateAmalgamatedComposition("..")
	if err != nil {
		return fmt.Errorf("failed to generate master composition module: %w", err)
	}

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

	location := os.Getenv("GOOGLE_CLOUD_LOCATION")
	if location == "" {
		location = "global"
	}

	vars := map[string]interface{}{
		"project_id": projectID,
		"project":    projectID,
		"projects":   []string{projectID},
		"region":     region,
		"location":   location,
	}

	planFile := "tfplan-master"
	tfOpts := &terraform.Options{
		TerraformDir: runnerDir,
		Vars:         vars,
		EnvVars: map[string]string{
			"GOOGLE_CLOUD_PROJECT": projectID,
		},
	}
	if isTFQuiet() {
		tfOpts.Logger = logger.Discard
	}

	_, _ = terraform.InitE(c.t, tfOpts)
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
	_, err = terraform.RunTerraformCommandE(c.t, tfOpts, args...)
	if err != nil {
		return fmt.Errorf("failed to generate plan for conftest: %w", err)
	}
	defer os.Remove(filepath.Join(runnerDir, planFile))

	planJSONStr, err := terraform.RunTerraformCommandE(c.t, tfOpts, "show", "-json", planFile)
	if err != nil {
		return fmt.Errorf("failed to show plan JSON: %w", err)
	}

	tmpJSONPath := filepath.Join(runnerDir, "tfplan.json")
	if err := os.WriteFile(tmpJSONPath, []byte(planJSONStr), 0644); err != nil {
		return fmt.Errorf("failed to write plan JSON: %w", err)
	}
	defer os.Remove(tmpJSONPath)

	ctx := context.Background()
	conftestCmd := shell.Command{
		Command:    "conftest",
		Args:       []string{"test", "tfplan.json", "--policy", "../../policies"},
		WorkingDir: runnerDir,
	}
	if isTFQuiet() {
		conftestCmd.Logger = logger.Discard
	}

	output, err := shell.RunCommandContextAndGetOutputE(c.t, ctx, &conftestCmd)
	if err != nil {
		return fmt.Errorf("OPA Conftest policy violation:\n%s", output)
	}
	return nil
}
