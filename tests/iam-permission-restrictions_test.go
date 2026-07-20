package test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type tfResource struct {
	// File where the Terraform resource was found.
	FilePath string
	// Terraform resource type, for example google_project_iam_binding.
	Type string
	// Terraform resource name label.
	Name string
	// Full resource block body between matching braces.
	Body string
}

func TestIAMSecurityGuardrails(t *testing.T) {
	t.Parallel()

	// Read all Terraform resources in the repository once, then reuse in each sub-test.
	repoRoot := "../.."
	resources, err := collectTerraformResources(repoRoot)
	assert.NoError(t, err)

	// Keep only IAM-related resources that are in scope for this control.
	iamResources := filterIAMResources(resources)

	t.Run("No Wildcard Permissions", func(t *testing.T) {
		// Block wildcard/public principals, wildcard roles, and wildcard permissions.
		for _, r := range iamResources {
			wildcardPrincipals := regexp.MustCompile(`(?i)allUsers|allAuthenticatedUsers|member\s*=\s*"[^"]*\*[^"]*"`)
			wildcardRoles := regexp.MustCompile(`(?m)^\s*role\s*=\s*"[^"]*\*[^"]*"`)
			wildcardPermissions := regexp.MustCompile(`(?s)permissions\s*=\s*\[[^\]]*\*[^\]]*\]`)

			assert.Falsef(t, wildcardPrincipals.MatchString(r.Body), "Wildcard principal found in %s (%s.%s)", r.FilePath, r.Type, r.Name)
			assert.Falsef(t, wildcardRoles.MatchString(r.Body), "Wildcard role found in %s (%s.%s)", r.FilePath, r.Type, r.Name)
			assert.Falsef(t, wildcardPermissions.MatchString(r.Body), "Wildcard permission found in %s (%s.%s)", r.FilePath, r.Type, r.Name)
		}
	})

	t.Run("Conditional Scoping at Trust Boundary", func(t *testing.T) {
		conditionBlock := regexp.MustCompile(`(?m)^\s*condition\s*\{`)

		for _, r := range iamResources {
			// IAM at org-level is broader than the expected trust boundary for this repo.
			assert.Falsef(t, strings.Contains(r.Type, "organization_iam_"), "Organization-level IAM binding is not allowed: %s (%s.%s)", r.FilePath, r.Type, r.Name)

			// For allow policy resources, require conditions to reduce privilege.
			assert.Truef(t, conditionBlock.MatchString(r.Body), "IAM binding must include a condition block: %s (%s.%s)", r.FilePath, r.Type, r.Name)
		}
	})

	t.Run("Service Account Scope Restriction", func(t *testing.T) {
		// Detect service-account members and static project/folder literals.
		saMember := regexp.MustCompile(`(?m)^\s*member\s*=\s*"serviceAccount:[^"]+"`)
		projectLiteral := regexp.MustCompile(`(?m)^\s*project\s*=\s*"([^"]+)"`)
		folderLiteral := regexp.MustCompile(`(?m)^\s*folder\s*=\s*"([^"]+)"`)

		for _, r := range iamResources {
			if !saMember.MatchString(r.Body) {
				continue
			}

			// Service account access must be scoped at folder/project level, not organization.
			assert.Falsef(t, strings.Contains(r.Type, "organization_iam_"), "Service account binding cannot be organization-scoped: %s (%s.%s)", r.FilePath, r.Type, r.Name)
			assert.Truef(t,
				strings.Contains(r.Type, "project_iam_") || strings.Contains(r.Type, "folder_iam_"),
				"Service account binding must be folder/project scoped: %s (%s.%s)", r.FilePath, r.Type, r.Name,
			)

			// If both scopes are static strings, enforce same environment token to avoid cross-environment access.
			saEnv := extractEnvToken(extractSAMemberValue(r.Body))
			scopeEnv := ""
			if m := projectLiteral.FindStringSubmatch(r.Body); len(m) > 1 {
				scopeEnv = extractEnvToken(m[1])
			}
			if scopeEnv == "" {
				if m := folderLiteral.FindStringSubmatch(r.Body); len(m) > 1 {
					scopeEnv = extractEnvToken(m[1])
				}
			}
			if saEnv != "" && scopeEnv != "" {
				assert.Equalf(t, scopeEnv, saEnv, "Potential cross-environment access detected in %s (%s.%s)", r.FilePath, r.Type, r.Name)
			}
		}
	})

	t.Run("TFE Pipeline SA Permission Restrictions", func(t *testing.T) {
		// Build resource -> role list once to simplify checks below.
		roles := extractRoleValues(iamResources)

		isTFEPipelineRoleSubject := func(resourceBody string) bool {
			lower := strings.ToLower(resourceBody)
			// Only enforce these restrictions for service accounts used by TFE/pipeline identities.
			return strings.Contains(lower, "serviceaccount:") && (strings.Contains(lower, "tfe") || strings.Contains(lower, "pipeline"))
		}

		dataPlaneRolePrefixes := []string{
			"roles/storage.",
			"roles/bigquery.",
			"roles/spanner.",
			"roles/sql.",
			"roles/pubsub.",
			"roles/datastore.",
			"roles/firestore.",
			"roles/secretmanager.secretAccessor",
			"roles/logging.privateLogViewer",
		}

		for _, r := range iamResources {
			if !isTFEPipelineRoleSubject(r.Body) {
				continue
			}

			resourceRoles := roles[fmt.Sprintf("%s|%s|%s", r.FilePath, r.Type, r.Name)]
			for _, role := range resourceRoles {
				roleLower := strings.ToLower(role)

				assert.NotContainsf(t, roleLower, "*", "Wildcard role is not allowed for TFE/pipeline SA: %s (%s.%s)", r.FilePath, r.Type, r.Name)
				assert.NotEqualf(t, "roles/owner", roleLower, "Overly broad role is not allowed for TFE/pipeline SA: %s (%s.%s)", r.FilePath, r.Type, r.Name)
				assert.NotEqualf(t, "roles/editor", roleLower, "Overly broad role is not allowed for TFE/pipeline SA: %s (%s.%s)", r.FilePath, r.Type, r.Name)

				for _, prefix := range dataPlaneRolePrefixes {
					assert.Falsef(t, strings.HasPrefix(roleLower, prefix), "Data-plane role is not allowed for TFE/pipeline SA: %s in %s (%s.%s)", role, r.FilePath, r.Type, r.Name)
				}
			}
		}
	})
}

func collectTerraformResources(root string) ([]tfResource, error) {
	var resources []tfResource

	// Match Terraform resource headers: resource "type" "name" {
	resourceHeader := regexp.MustCompile(`resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".tf") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)

		// Find each resource header and then capture the full block using brace matching.
		matches := resourceHeader.FindAllStringSubmatchIndex(content, -1)
		for _, idx := range matches {
			typeStart, typeEnd := idx[2], idx[3]
			nameStart, nameEnd := idx[4], idx[5]
			headerEnd := idx[1]

			openBrace := strings.LastIndex(content[:headerEnd], "{")
			if openBrace == -1 {
				continue
			}

			closeBrace := findMatchingBrace(content, openBrace)
			if closeBrace == -1 {
				continue
			}

			resources = append(resources, tfResource{
				FilePath: filepath.ToSlash(path),
				Type:     content[typeStart:typeEnd],
				Name:     content[nameStart:nameEnd],
				Body:     content[openBrace : closeBrace+1],
			})
		}

		return nil
	})

	return resources, err
}

func filterIAMResources(resources []tfResource) []tfResource {
	// Keep IAM resources only, excluding deny rules for this specific control scope.
	filtered := make([]tfResource, 0)
	for _, r := range resources {
		lowerType := strings.ToLower(r.Type)
		lowerName := strings.ToLower(r.Name)
		lowerBody := strings.ToLower(r.Body)

		if !strings.Contains(lowerType, "_iam_") {
			continue
		}
		// Exclude DENY resources per control requirement.
		if strings.Contains(lowerType, "deny") || strings.Contains(lowerName, "deny") || strings.Contains(lowerBody, "deny") {
			continue
		}

		filtered = append(filtered, r)
	}

	return filtered
}

func extractRoleValues(resources []tfResource) map[string][]string {
	// Extract role = "..." values per resource key.
	roleRe := regexp.MustCompile(`(?m)^\s*role\s*=\s*"([^"]+)"`)
	out := make(map[string][]string)

	for _, r := range resources {
		key := fmt.Sprintf("%s|%s|%s", r.FilePath, r.Type, r.Name)
		for _, match := range roleRe.FindAllStringSubmatch(r.Body, -1) {
			if len(match) > 1 {
				out[key] = append(out[key], strings.TrimSpace(match[1]))
			}
		}
	}

	return out
}

func extractSAMemberValue(body string) string {
	// Return the service account email part from member = "serviceAccount:<email>".
	re := regexp.MustCompile(`(?m)^\s*member\s*=\s*"serviceAccount:([^"]+)"`)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func extractEnvToken(value string) string {
	value = strings.ToLower(value)
	// Common environment tokens used in GCP naming conventions.
	re := regexp.MustCompile(`(^|[-_.])(dev|qa|uat|nprd|se|prd|prod)($|[-_.])`)
	m := re.FindStringSubmatch(value)
	if len(m) < 3 {
		return ""
	}
	return m[2]
}

func findMatchingBrace(s string, openIdx int) int {
	// Walk the text and find the closing brace that pairs with openIdx,
	// while ignoring braces inside quoted strings.
	depth := 0
	inString := false
	escaped := false

	for i := openIdx; i < len(s); i++ {
		ch := s[i]

		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			inString = true
			continue
		}
		if ch == '{' {
			depth++
			continue
		}
		if ch == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}