package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	iamScopeProject      = "project"
	iamScopeFolder       = "folder"
	iamScopeOrganization = "organization"
	memberAllUsers        = "allUsers"
	memberAllAuthenticated = "allAuthenticatedUsers"
	memberWildcard        = "*"
)

var iamResourceTypeScope = map[string]string{
	"google_project_iam_binding":      iamScopeProject,
	"google_project_iam_member":       iamScopeProject,
	"google_folder_iam_binding":       iamScopeFolder,
	"google_folder_iam_member":        iamScopeFolder,
	"google_organization_iam_binding": iamScopeOrganization,
	"google_organization_iam_member":  iamScopeOrganization,
}

var restrictedDataPlaneRoles = []string{
	"roles/owner",
	"roles/editor",
	"roles/storage.admin",
	"roles/storage.objectAdmin",
	"roles/bigquery.admin",
	"roles/bigquery.dataEditor",
	"roles/cloudsql.admin",
	"roles/secretmanager.secretAccessor",
	"roles/iam.securityAdmin",
	"roles/compute.admin",
	"roles/container.admin",
}

type IAMBinding struct {
	ResourceType string
	ResourceName string
	Scope        string
	Role         string
	Members      []string
	HasCondition bool
	FilePath     string
}

type GuardrailViolation struct {
	Rule     string
	Resource string
	Message  string
	FilePath string
}

func (v GuardrailViolation) String() string {
	return fmt.Sprintf("[%s] %s (%s): %s", v.Rule, v.Resource, v.FilePath, v.Message)
}

func findTFFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".tf") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func stripComments(content string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			out = append(out, "")
		} else {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func findMatchingBrace(s string, openPos int) int {
	if openPos < 0 || openPos >= len(s) || s[openPos] != '{' {
		return -1
	}
	depth := 0
	for i := openPos; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func extractFieldValue(block, field string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"`, regexp.QuoteMeta(field)))
	if m := re.FindStringSubmatch(block); len(m) >= 2 {
		return m[1]
	}
	return ""
}

func extractMembers(block string) []string {
	if m := regexp.MustCompile(`(?s)members\s*=\s*\[([^\]]*)\]`).FindStringSubmatch(block); len(m) >= 2 {
		var members []string
		for _, item := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			if len(item) >= 2 {
				members = append(members, item[1])
			}
		}
		return members
	}
	if m := regexp.MustCompile(`(?m)^\s*member\s*=\s*"([^"]+)"`).FindStringSubmatch(block); len(m) >= 2 {
		return []string{m[1]}
	}
	return nil
}

func hasConditionBlock(block string) bool {
	return regexp.MustCompile(`(?m)\bcondition\s*\{`).MatchString(block)
}

func isTFEPipelineMember(members []string) bool {
	for _, m := range members {
		lower := strings.ToLower(m)
		if strings.Contains(lower, "tfe") || strings.Contains(lower, "pipeline") {
			return true
		}
	}
	return false
}

func isWildcardMember(member string) bool {
	switch member {
	case memberAllUsers, memberAllAuthenticated, memberWildcard:
		return true
	}
	return strings.Contains(member, "*")
}

func parseTFContent(content, filePath string) []IAMBinding {
	cleaned := stripComments(content)
	headerRe := regexp.MustCompile(`resource\s+"(google_[a-z_]+_iam_(?:binding|member))"\s+"([^"]+)"\s*\{`)
	var bindings []IAMBinding
	for _, loc := range headerRe.FindAllStringSubmatchIndex(cleaned, -1) {
		resourceType := cleaned[loc[2]:loc[3]]
		resourceName := cleaned[loc[4]:loc[5]]
		if strings.Contains(resourceType, "_deny") {
			continue
		}
		scope, known := iamResourceTypeScope[resourceType]
		if !known {
			continue
		}
		fullMatch := cleaned[loc[0]:loc[1]]
		relOpen := strings.Index(fullMatch, "{")
		if relOpen == -1 {
			continue
		}
		closePos := findMatchingBrace(cleaned, loc[0]+relOpen)
		if closePos == -1 {
			continue
		}
		blockBody := cleaned[loc[0]+relOpen+1 : closePos]
		bindings = append(bindings, IAMBinding{
			ResourceType: resourceType,
			ResourceName: resourceName,
			Scope:        scope,
			Role:         extractFieldValue(blockBody, "role"),
			Members:      extractMembers(blockBody),
			HasCondition: hasConditionBlock(blockBody),
			FilePath:     filePath,
		})
	}
	return bindings
}

func loadBindingsFromDir(dir string) ([]IAMBinding, error) {
	files, err := findTFFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("findTFFiles(%q): %w", dir, err)
	}
	var all []IAMBinding
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		all = append(all, parseTFContent(string(raw), f)...)
	}
	return all, nil
}

func validateNoWildcards(bindings []IAMBinding) []GuardrailViolation {
	var out []GuardrailViolation
	for _, b := range bindings {
		res := b.ResourceType + "." + b.ResourceName
		if b.Role == memberWildcard || strings.Contains(b.Role, "*") {
			out = append(out, GuardrailViolation{"NoWildcards", res, fmt.Sprintf("wildcard role %q not permitted", b.Role), b.FilePath})
		}
		for _, m := range b.Members {
			if isWildcardMember(m) {
				out = append(out, GuardrailViolation{"NoWildcards", res, fmt.Sprintf("wildcard/public principal %q not permitted", m), b.FilePath})
			}
		}
	}
	return out
}

func validateNoOrgBindings(bindings []IAMBinding) []GuardrailViolation {
	var out []GuardrailViolation
	for _, b := range bindings {
		if b.Scope == iamScopeOrganization {
			out = append(out, GuardrailViolation{
				"NoOrgLevelBindings",
				b.ResourceType + "." + b.ResourceName,
				fmt.Sprintf("resource type %q targets organization scope; use project or folder", b.ResourceType),
				b.FilePath,
			})
		}
	}
	return out
}

func validateConditionsPresent(bindings []IAMBinding) []GuardrailViolation {
	var out []GuardrailViolation
	for _, b := range bindings {
		if !b.HasCondition {
			out = append(out, GuardrailViolation{
				"ConditionsRequired",
				b.ResourceType + "." + b.ResourceName,
				"IAM binding missing required condition {} block",
				b.FilePath,
			})
		}
	}
	return out
}

func validateScopeIsProjectOrFolder(bindings []IAMBinding) []GuardrailViolation {
	var out []GuardrailViolation
	for _, b := range bindings {
		if b.Scope != iamScopeProject && b.Scope != iamScopeFolder {
			out = append(out, GuardrailViolation{
				"ScopeProjectOrFolder",
				b.ResourceType + "." + b.ResourceName,
				fmt.Sprintf("scope %q not permitted; use project or folder only", b.Scope),
				b.FilePath,
			})
		}
	}
	return out
}

func validateTFEPipelineSA(bindings []IAMBinding) []GuardrailViolation {
	restricted := make(map[string]struct{}, len(restrictedDataPlaneRoles))
	for _, r := range restrictedDataPlaneRoles {
		restricted[r] = struct{}{}
	}
	var out []GuardrailViolation
	for _, b := range bindings {
		if !isTFEPipelineMember(b.Members) {
			continue
		}
		res := b.ResourceType + "." + b.ResourceName
		if b.Role == memberWildcard || strings.Contains(b.Role, "*") {
			out = append(out, GuardrailViolation{"TFEPipelineSARestrictions", res, fmt.Sprintf("TFE pipeline SA: wildcard role %q forbidden", b.Role), b.FilePath})
			continue
		}
		if _, forbidden := restricted[b.Role]; forbidden {
			out = append(out, GuardrailViolation{"TFEPipelineSARestrictions", res, fmt.Sprintf("TFE pipeline SA: role %q violates least-privilege", b.Role), b.FilePath})
		}
	}
	return out
}

func runAllGuardrails(bindings []IAMBinding) []GuardrailViolation {
	var all []GuardrailViolation
	all = append(all, validateNoWildcards(bindings)...)
	all = append(all, validateNoOrgBindings(bindings)...)
	all = append(all, validateConditionsPresent(bindings)...)
	all = append(all, validateScopeIsProjectOrFolder(bindings)...)
	all = append(all, validateTFEPipelineSA(bindings)...)
	return all
}

func formatViolations(violations []GuardrailViolation) string {
	if len(violations) == 0 {
		return "(none)"
	}
	sb := &strings.Builder{}
	for i, v := range violations {
		fmt.Fprintf(sb, "  %d. %s\n", i+1, v.String())
	}
	return sb.String()
}

func containsSubstr(violations []GuardrailViolation, substr string) bool {
	for _, v := range violations {
		if strings.Contains(v.Message, substr) {
			return true
		}
	}
	return false
}

func TestFindTFFiles(t *testing.T) {
	t.Parallel()
	files, err := findTFFiles(filepath.Join("testdata", "iam"))
	require.NoError(t, err)
	assert.NotEmpty(t, files)
	for _, f := range files {
		assert.True(t, strings.HasSuffix(f, ".tf"), "unexpected file: %s", f)
	}
}

func TestFindTFFiles_NonExistentDir(t *testing.T) {
	t.Parallel()
	_, err := findTFFiles(filepath.Join("testdata", "nonexistent"))
	assert.Error(t, err)
}

func TestFindMatchingBrace(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		openPos int
		want    int
	}{
		{"simple block", `{ foo = "bar" }`, 0, 14},
		{"nested", `{ a { b = 1 } c = 2 }`, 0, 21},
		{"deeply nested", `{ a { b { c = 3 } } }`, 0, 20},
		{"inner only", `{ a { b = 1 } c = 2 }`, 4, 12},
		{"unmatched returns -1", `{ foo = "bar"`, 0, -1},
		{"not opening brace returns -1", `} foo {`, 0, -1},
		{"out of range returns -1", `{}`, 99, -1},
		{"empty block", `{}`, 0, 1},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, findMatchingBrace(tc.input, tc.openPos))
		})
	}
}

func TestExtractFieldValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		block, field, want string
	}{
		{`  role = "roles/viewer"`, "role", "roles/viewer"},
		{`  project = "my-project"`, "project", "my-project"},
		{`  role   =   "roles/editor"`, "role", "roles/editor"},
		{`  role = "*"`, "role", "*"},
		{`  member = "serviceAccount:x@y.iam.gserviceaccount.com"`, "role", ""},
		{``, "role", ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.field+":"+tc.want, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, extractFieldValue(tc.block, tc.field))
		})
	}
}

func TestExtractMembers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		block string
		want  []string
	}{
		{
			"members list",
			`  members = ["serviceAccount:a@p.iam.gserviceaccount.com","serviceAccount:b@p.iam.gserviceaccount.com"]`,
			[]string{"serviceAccount:a@p.iam.gserviceaccount.com", "serviceAccount:b@p.iam.gserviceaccount.com"},
		},
		{"singular member", `  member = "serviceAccount:sa@p.iam.gserviceaccount.com"`, []string{"serviceAccount:sa@p.iam.gserviceaccount.com"}},
		{"allUsers in list", `  members = [ "allUsers" ]`, []string{"allUsers"}},
		{"allAuthenticatedUsers singular", `  member = "allAuthenticatedUsers"`, []string{"allAuthenticatedUsers"}},
		{"no member field", `  role = "roles/viewer"`, nil},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, extractMembers(tc.block))
		})
	}
}

func TestHasConditionBlock(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		block string
		want  bool
	}{
		{"with condition", "  condition {\n    title = \"x\"\n  }", true},
		{"without condition", `  role = "roles/viewer"`, false},
		{"empty block", ``, false},
		{"condition in member email no brace", `  member = "serviceAccount:condition-sa@p.iam.gserviceaccount.com"`, false},
		{"inline condition", `  condition { title = "t"; expression = "true" }`, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, hasConditionBlock(tc.block))
		})
	}
}

func TestIsTFEPipelineMember(t *testing.T) {
	t.Parallel()
	tests := []struct {
		members []string
		want    bool
	}{
		{[]string{"serviceAccount:tfe-runner@p.iam.gserviceaccount.com"}, true},
		{[]string{"serviceAccount:TFE-Runner@p.iam.gserviceaccount.com"}, true},
		{[]string{"serviceAccount:pipeline-deployer@p.iam.gserviceaccount.com"}, true},
		{[]string{"serviceAccount:app-backend@p.iam.gserviceaccount.com"}, false},
		{[]string{}, false},
		{nil, false},
		{[]string{"serviceAccount:app@p.iam.gserviceaccount.com", "serviceAccount:tfe@p.iam.gserviceaccount.com"}, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(strings.Join(tc.members, ","), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isTFEPipelineMember(tc.members))
		})
	}
}

func TestIsWildcardMember(t *testing.T) {
	t.Parallel()
	tests := []struct {
		member string
		want   bool
	}{
		{memberAllUsers, true},
		{memberAllAuthenticated, true},
		{memberWildcard, true},
		{"serviceAccount:*", true},
		{"user:*@example.com", true},
		{"serviceAccount:sa@p.iam.gserviceaccount.com", false},
		{"user:alice@example.com", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.member, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isWildcardMember(tc.member))
		})
	}
}

func TestParseTFContent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		content   string
		wantCount int
		spot      *IAMBinding
	}{
		{
			"project binding with condition",
			`resource "google_project_iam_binding" "viewer" {
  project = "my-project"
  role    = "roles/viewer"
  members = ["serviceAccount:sa@p.iam.gserviceaccount.com"]
  condition { title = "t"; expression = "true" }
}`,
			1,
			&IAMBinding{ResourceType: "google_project_iam_binding", ResourceName: "viewer", Scope: iamScopeProject, Role: "roles/viewer", HasCondition: true},
		},
		{
			"org binding parsed as org scope",
			`resource "google_organization_iam_member" "bad" {
  org_id = "123"
  role   = "roles/editor"
  member = "serviceAccount:sa@p.iam.gserviceaccount.com"
  condition { title = "c"; expression = "true" }
}`,
			1,
			&IAMBinding{Scope: iamScopeOrganization, HasCondition: true},
		},
		{
			"iam deny skipped",
			`resource "google_project_iam_deny" "deny" { parent = "projects/p" }`,
			0, nil,
		},
		{
			"non-iam resource skipped",
			`resource "google_storage_bucket" "b" { name = "b" }`,
			0, nil,
		},
		{
			"missing condition detected",
			`resource "google_project_iam_member" "no_cond" {
  project = "p"
  role    = "roles/viewer"
  member  = "serviceAccount:a@p.iam.gserviceaccount.com"
}`,
			1,
			&IAMBinding{HasCondition: false},
		},
		{
			"multiple bindings in one file",
			`resource "google_project_iam_member" "one" {
  project = "p"; role = "roles/viewer"; member = "serviceAccount:a@p.iam.gserviceaccount.com"
  condition { title = "t"; expression = "true" }
}
resource "google_folder_iam_binding" "two" {
  folder = "folders/123"; role = "roles/logging.logWriter"
  members = ["serviceAccount:b@p.iam.gserviceaccount.com"]
  condition { title = "t"; expression = "true" }
}`,
			2, nil,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseTFContent(tc.content, "test.tf")
			require.Len(t, got, tc.wantCount)
			if tc.spot != nil && len(got) > 0 {
				b := got[0]
				if tc.spot.ResourceType != "" {
					assert.Equal(t, tc.spot.ResourceType, b.ResourceType)
				}
				if tc.spot.Scope != "" {
					assert.Equal(t, tc.spot.Scope, b.Scope)
				}
				if tc.spot.Role != "" {
					assert.Equal(t, tc.spot.Role, b.Role)
				}
				assert.Equal(t, tc.spot.HasCondition, b.HasCondition)
			}
		})
	}
}

func TestParseTFContent_EdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		content   string
		wantCount int
	}{
		{"empty string", "", 0},
		{"only whitespace", "   \n\t\n   ", 0},
		{"only comments", "# comment\n// another", 0},
		{"malformed missing brace", "resource \"google_project_iam_binding\" \"x\" {\n  role = \"roles/viewer\"", 0},
		{"org deny skipped", "resource \"google_organization_iam_deny\" \"d\" { parent = \"organizations/123\" }", 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Len(t, parseTFContent(tc.content, "edge.tf"), tc.wantCount)
		})
	}
}

func TestValidateNoWildcards(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		bindings  []IAMBinding
		wantCount int
		wantMsg   string
	}{
		{"clean binding", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "ok", Role: "roles/viewer", Members: []string{"serviceAccount:sa@p.iam.gserviceaccount.com"}}}, 0, ""},
		{"wildcard role", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "wr", Role: "*", Members: []string{"serviceAccount:sa@p.iam.gserviceaccount.com"}}}, 1, "wildcard role"},
		{"allUsers member", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "au", Role: "roles/viewer", Members: []string{"allUsers"}}}, 1, "allUsers"},
		{"allAuthenticatedUsers", []IAMBinding{{ResourceType: "google_project_iam_member", ResourceName: "aa", Role: "roles/viewer", Members: []string{"allAuthenticatedUsers"}}}, 1, "allAuthenticatedUsers"},
		{"glob in SA", []IAMBinding{{ResourceType: "google_project_iam_member", ResourceName: "sg", Role: "roles/viewer", Members: []string{"serviceAccount:*"}}}, 1, ""},
		{"multiple violations", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "mb", Role: "*", Members: []string{"allUsers", "allAuthenticatedUsers"}}}, 3, ""},
		{"nil input", nil, 0, ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := validateNoWildcards(tc.bindings)
			assert.Len(t, got, tc.wantCount)
			if tc.wantMsg != "" {
				assert.True(t, containsSubstr(got, tc.wantMsg), "expected message containing %q in %v", tc.wantMsg, got)
			}
		})
	}
}

func TestValidateNoOrgBindings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		bindings  []IAMBinding
		wantCount int
	}{
		{"project — ok", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "ok", Scope: iamScopeProject}}, 0},
		{"folder — ok", []IAMBinding{{ResourceType: "google_folder_iam_member", ResourceName: "ok", Scope: iamScopeFolder}}, 0},
		{"org binding — fail", []IAMBinding{{ResourceType: "google_organization_iam_binding", ResourceName: "bad", Scope: iamScopeOrganization}}, 1},
		{"org member — fail", []IAMBinding{{ResourceType: "google_organization_iam_member", ResourceName: "bad", Scope: iamScopeOrganization}}, 1},
		{"mixed — only org flagged", []IAMBinding{
			{ResourceType: "google_project_iam_binding", ResourceName: "ok", Scope: iamScopeProject},
			{ResourceType: "google_organization_iam_binding", ResourceName: "bad", Scope: iamScopeOrganization},
			{ResourceType: "google_folder_iam_member", ResourceName: "ok2", Scope: iamScopeFolder},
		}, 1},
		{"empty", []IAMBinding{}, 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Len(t, validateNoOrgBindings(tc.bindings), tc.wantCount)
		})
	}
}

func TestValidateConditionsPresent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		bindings  []IAMBinding
		wantCount int
	}{
		{"has condition", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "ok", HasCondition: true}}, 0},
		{"missing condition", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "bad", HasCondition: false}}, 1},
		{"mixed", []IAMBinding{
			{ResourceType: "google_project_iam_binding", ResourceName: "ok", HasCondition: true},
			{ResourceType: "google_folder_iam_member", ResourceName: "bad", HasCondition: false},
		}, 1},
		{"all missing", []IAMBinding{
			{ResourceType: "google_project_iam_binding", ResourceName: "a", HasCondition: false},
			{ResourceType: "google_project_iam_member", ResourceName: "b", HasCondition: false},
		}, 2},
		{"empty", []IAMBinding{}, 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := validateConditionsPresent(tc.bindings)
			assert.Len(t, got, tc.wantCount)
			for _, v := range got {
				assert.Contains(t, v.Message, "condition")
				assert.Equal(t, "ConditionsRequired", v.Rule)
			}
		})
	}
}

func TestValidateScopeIsProjectOrFolder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		bindings  []IAMBinding
		wantCount int
	}{
		{"project — ok", []IAMBinding{{Scope: iamScopeProject}}, 0},
		{"folder — ok", []IAMBinding{{Scope: iamScopeFolder}}, 0},
		{"org — fail", []IAMBinding{{Scope: iamScopeOrganization, ResourceType: "google_organization_iam_binding", ResourceName: "bad"}}, 1},
		{"unknown scope — fail", []IAMBinding{{Scope: "workspace", ResourceType: "google_other_iam_binding", ResourceName: "unknown"}}, 1},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Len(t, validateScopeIsProjectOrFolder(tc.bindings), tc.wantCount)
		})
	}
}

func TestValidateTFEPipelineSA(t *testing.T) {
	t.Parallel()
	sa := func(name string) []string {
		return []string{"serviceAccount:" + name + "@p.iam.gserviceaccount.com"}
	}
	tests := []struct {
		name      string
		bindings  []IAMBinding
		wantCount int
	}{
		{"non-TFE SA owner — no TFE check", []IAMBinding{{ResourceType: "google_project_iam_member", ResourceName: "app", Role: "roles/owner", Members: sa("app")}}, 0},
		{"TFE SA safe role", []IAMBinding{{ResourceType: "google_project_iam_member", ResourceName: "tfe_safe", Role: "roles/compute.viewer", Members: sa("tfe-sa"), HasCondition: true}}, 0},
		{"TFE SA roles/owner", []IAMBinding{{ResourceType: "google_project_iam_member", ResourceName: "tfe_owner", Role: "roles/owner", Members: sa("tfe-deployer")}}, 1},
		{"TFE SA roles/editor", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "pipe_editor", Role: "roles/editor", Members: sa("pipeline-sa")}}, 1},
		{"TFE SA roles/storage.admin", []IAMBinding{{ResourceType: "google_project_iam_member", ResourceName: "tfe_storage", Role: "roles/storage.admin", Members: sa("tfe-sa")}}, 1},
		{"TFE SA wildcard role", []IAMBinding{{ResourceType: "google_project_iam_member", ResourceName: "tfe_wild", Role: "*", Members: sa("tfe-sa")}}, 1},
		{"pipeline SA multiple restricted roles", []IAMBinding{
			{ResourceType: "google_project_iam_member", ResourceName: "r1", Role: "roles/compute.admin", Members: sa("pipeline-runner")},
			{ResourceType: "google_project_iam_member", ResourceName: "r2", Role: "roles/container.admin", Members: sa("pipeline-runner")},
			{ResourceType: "google_project_iam_member", ResourceName: "r3", Role: "roles/bigquery.admin", Members: sa("pipeline-runner")},
		}, 3},
		{"TFE SA iam.roleViewer — safe", []IAMBinding{{ResourceType: "google_project_iam_binding", ResourceName: "tfe_iam_viewer", Role: "roles/iam.roleViewer", Members: sa("tfe-sa"), HasCondition: true}}, 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Len(t, validateTFEPipelineSA(tc.bindings), tc.wantCount)
		})
	}
}

func TestRunAllGuardrails_Empty(t *testing.T) {
	t.Parallel()
	assert.Empty(t, runAllGuardrails([]IAMBinding{}))
}

func TestRunAllGuardrails_MaximallyBadBinding(t *testing.T) {
	t.Parallel()
	bindings := []IAMBinding{{
		ResourceType: "google_organization_iam_binding",
		ResourceName: "catastrophic",
		Scope:        iamScopeOrganization,
		Role:         "*",
		Members:      []string{"allUsers", "allAuthenticatedUsers"},
		HasCondition: false,
		FilePath:     "test.tf",
	}}
	violations := runAllGuardrails(bindings)
	assert.GreaterOrEqual(t, len(violations), 5)
	rules := make(map[string]bool)
	for _, v := range violations {
		rules[v.Rule] = true
	}
	assert.True(t, rules["NoWildcards"])
	assert.True(t, rules["NoOrgLevelBindings"])
	assert.True(t, rules["ConditionsRequired"])
	assert.True(t, rules["ScopeProjectOrFolder"])
}

func TestGuardrailViolation_String(t *testing.T) {
	t.Parallel()
	v := GuardrailViolation{"NoWildcards", "google_project_iam_binding.bad", "wildcard role not permitted", "iam.tf"}
	s := v.String()
	assert.Contains(t, s, "NoWildcards")
	assert.Contains(t, s, "google_project_iam_binding.bad")
	assert.Contains(t, s, "wildcard role")
	assert.Contains(t, s, "iam.tf")
}

func TestIAMGuardrailsIntegration(t *testing.T) {
	t.Parallel()
	testdataDir := filepath.Join("testdata", "iam")
	tests := []struct {
		file          string
		wantFail      bool
		expectedRules []string
	}{
		{"valid_project_binding.tf", false, nil},
		{"valid_folder_binding.tf", false, nil},
		{"valid_tfe_sa_binding.tf", false, nil},
		{"invalid_wildcard_role.tf", true, []string{"NoWildcards"}},
		{"invalid_wildcard_member.tf", true, []string{"NoWildcards"}},
		{"invalid_org_binding.tf", true, []string{"NoOrgLevelBindings", "ScopeProjectOrFolder"}},
		{"invalid_no_condition.tf", true, []string{"ConditionsRequired"}},
		{"invalid_owner_role.tf", true, []string{"TFEPipelineSARestrictions"}},
		{"invalid_editor_role.tf", true, []string{"TFEPipelineSARestrictions"}},
		{"invalid_data_plane_role.tf", true, []string{"TFEPipelineSARestrictions"}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join(testdataDir, tc.file))
			require.NoError(t, err)
			violations := runAllGuardrails(parseTFContent(string(raw), tc.file))
			if tc.wantFail {
				assert.NotEmpty(t, violations, "file %s: expected violations but got none", tc.file)
				if len(tc.expectedRules) > 0 {
					found := false
					for _, v := range violations {
						for _, r := range tc.expectedRules {
							if v.Rule == r {
								found = true
								break
							}
						}
						if found {
							break
						}
					}
					assert.True(t, found, "file %s: expected rules %v, got:\n%s", tc.file, tc.expectedRules, formatViolations(violations))
				}
			} else {
				assert.Empty(t, violations, "file %s: unexpected violations:\n%s", tc.file, formatViolations(violations))
			}
		})
	}
}

func TestIAMGuardrailsFullDirectory(t *testing.T) {
	t.Parallel()
	allBindings, err := loadBindingsFromDir(filepath.Join("testdata", "iam"))
	require.NoError(t, err)
	require.NotEmpty(t, allBindings)

	var validB, invalidB []IAMBinding
	for _, b := range allBindings {
		base := filepath.Base(b.FilePath)
		if strings.HasPrefix(base, "valid_") {
			validB = append(validB, b)
		} else if strings.HasPrefix(base, "invalid_") {
			invalidB = append(invalidB, b)
		}
	}

	t.Run("valid_fixtures_no_violations", func(t *testing.T) {
		t.Parallel()
		violations := runAllGuardrails(validB)
		assert.Empty(t, violations, "valid fixtures must not produce violations:\n%s", formatViolations(violations))
	})

	t.Run("invalid_fixtures_have_violations", func(t *testing.T) {
		t.Parallel()
		require.NotEmpty(t, invalidB)
		assert.NotEmpty(t, runAllGuardrails(invalidB))
	})
}
