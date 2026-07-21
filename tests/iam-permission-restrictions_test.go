package tests

import (
	"fmt"
	"strings"

	"github.com/cucumber/godog"
)

type iamRestrictionsState struct {
	plannedChanges []PlanResourceChange
}

var iamState iamRestrictionsState

func (c *bddContext) registerIAMPermissionRestrictionsSteps(sc *godog.ScenarioContext) {
	sc.Step(`^I run terraform plan on all modules$`, c.iRunTerraformPlanOnAllModules)
	sc.Step(`^no wildcard principals, wildcard roles, or wildcard permissions should be allowed$`, c.noWildcardPermissionsAllowed)
	sc.Step(`^all IAM resources must include a condition block$`, c.allIAMResourcesMustIncludeCondition)
	sc.Step(`^no organization-level IAM bindings are allowed$`, c.noOrganizationLevelIAMBindingsAllowed)
	sc.Step(`^service account bindings must be folder or project scoped$`, c.serviceAccountBindingsMustBeFolderOrProjectScoped)
	sc.Step(`^no cross-environment service account access should be detected$`, c.noCrossEnvironmentServiceAccountAccess)
	sc.Step(`^pipeline service accounts must not be granted wildcard, owner, editor, or data-plane roles$`, c.pipelineServiceAccountsRestrictions)
}

func (c *bddContext) iRunTerraformPlanOnAllModules() error {
	changes, err := getRepositoryPlanChanges(c.t)
	if err != nil {
		return err
	}
	iamState.plannedChanges = changes
	return nil
}

func (c *bddContext) noWildcardPermissionsAllowed() error {
	var violations []string

	for _, rc := range iamState.plannedChanges {
		if !isIAMResource(rc.Type) {
			continue
		}

		after := rc.Change.After
		if after == nil {
			continue
		}

		member := getStringVal(after, "member")
		if member != "" {
			if member == "allUsers" || member == "allAuthenticatedUsers" || strings.Contains(member, "*") {
				violations = append(violations, fmt.Sprintf("Wildcard principal found in %s: member=%s", rc.Address, member))
			}
		}

		members := getSliceOfStrings(after, "members")
		for _, m := range members {
			if m == "allUsers" || m == "allAuthenticatedUsers" || strings.Contains(m, "*") {
				violations = append(violations, fmt.Sprintf("Wildcard principal found in %s: members contains %s", rc.Address, m))
			}
		}

		role := getStringVal(after, "role")
		if role != "" {
			if strings.Contains(role, "*") {
				violations = append(violations, fmt.Sprintf("Wildcard role found in %s: role=%s", rc.Address, role))
			}
		}

		permissions := getSliceOfStrings(after, "permissions")
		for _, p := range permissions {
			if strings.Contains(p, "*") {
				violations = append(violations, fmt.Sprintf("Wildcard permission found in %s: permissions contains %s", rc.Address, p))
			}
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("wildcard permission violations: %v", violations)
	}
	return nil
}

func (c *bddContext) allIAMResourcesMustIncludeCondition() error {
	var violations []string
	for _, rc := range iamState.plannedChanges {
		if !isIAMResource(rc.Type) {
			continue
		}

		after := rc.Change.After
		if after == nil {
			continue
		}

		condition, ok := after["condition"]
		if !ok || condition == nil {
			violations = append(violations, fmt.Sprintf("IAM binding must include a condition block: %s (%s)", rc.Address, rc.Type))
			continue
		}

		slice, ok := condition.([]interface{})
		if !ok || len(slice) == 0 {
			violations = append(violations, fmt.Sprintf("IAM binding must include a condition block: %s (%s)", rc.Address, rc.Type))
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("IAM condition block violations: %v", violations)
	}
	return nil
}

func (c *bddContext) noOrganizationLevelIAMBindingsAllowed() error {
	var violations []string
	for _, rc := range iamState.plannedChanges {
		if isIAMResource(rc.Type) {
			if strings.Contains(strings.ToLower(rc.Type), "organization_iam_") {
				violations = append(violations, fmt.Sprintf("Organization-level IAM binding is not allowed: %s", rc.Address))
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("organization-level IAM binding violations: %v", violations)
	}
	return nil
}

func (c *bddContext) serviceAccountBindingsMustBeFolderOrProjectScoped() error {
	var violations []string
	for _, rc := range iamState.plannedChanges {
		if !isIAMResource(rc.Type) {
			continue
		}

		after := rc.Change.After
		if after == nil {
			continue
		}

		var saMembers []string
		member := getStringVal(after, "member")
		if member != "" && strings.HasPrefix(strings.ToLower(member), "serviceaccount:") {
			saMembers = append(saMembers, member)
		}
		members := getSliceOfStrings(after, "members")
		for _, m := range members {
			if strings.HasPrefix(strings.ToLower(m), "serviceaccount:") {
				saMembers = append(saMembers, m)
			}
		}

		if len(saMembers) == 0 {
			continue
		}

		if strings.Contains(strings.ToLower(rc.Type), "organization_iam_") {
			violations = append(violations, fmt.Sprintf("Service account binding cannot be organization-scoped: %s", rc.Address))
		}
		if !strings.Contains(strings.ToLower(rc.Type), "project_iam_") && !strings.Contains(strings.ToLower(rc.Type), "folder_iam_") {
			violations = append(violations, fmt.Sprintf("Service account binding must be folder/project scoped: %s (%s)", rc.Address, rc.Type))
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("service account scope violations: %v", violations)
	}
	return nil
}

func (c *bddContext) noCrossEnvironmentServiceAccountAccess() error {
	var violations []string
	for _, rc := range iamState.plannedChanges {
		if !isIAMResource(rc.Type) {
			continue
		}

		after := rc.Change.After
		if after == nil {
			continue
		}

		var scopeVal string
		if pVal, ok := after["project"]; ok {
			if pStr, ok := pVal.(string); ok {
				scopeVal = pStr
			}
		}
		if scopeVal == "" {
			if fVal, ok := after["folder"]; ok {
				if fStr, ok := fVal.(string); ok {
					scopeVal = fStr
				}
			}
		}

		if scopeVal == "" {
			continue
		}
		scopeEnv := extractEnvToken(scopeVal)
		if scopeEnv == "" {
			continue
		}

		var saMembers []string
		member := getStringVal(after, "member")
		if member != "" && strings.HasPrefix(strings.ToLower(member), "serviceaccount:") {
			saMembers = append(saMembers, member)
		}
		members := getSliceOfStrings(after, "members")
		for _, m := range members {
			if strings.HasPrefix(strings.ToLower(m), "serviceaccount:") {
				saMembers = append(saMembers, m)
			}
		}

		for _, sa := range saMembers {
			email := sa
			if idx := strings.Index(strings.ToLower(sa), "serviceaccount:"); idx != -1 {
				email = sa[idx+len("serviceAccount:"):]
			}

			saEnv := extractEnvToken(email)
			if saEnv != "" {
				if scopeEnv != saEnv {
					violations = append(violations, fmt.Sprintf("Potential cross-environment access detected in %s: scope env %q does not match service account env %q", rc.Address, scopeEnv, saEnv))
				}
			}
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("cross-environment service account access violations: %v", violations)
	}
	return nil
}

func (c *bddContext) pipelineServiceAccountsRestrictions() error {
	var violations []string

	isPipelineSA := func(member string) bool {
		lower := strings.ToLower(member)
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

	for _, rc := range iamState.plannedChanges {
		if !isIAMResource(rc.Type) {
			continue
		}

		after := rc.Change.After
		if after == nil {
			continue
		}

		var saMembers []string
		member := getStringVal(after, "member")
		if member != "" && isPipelineSA(member) {
			saMembers = append(saMembers, member)
		}
		members := getSliceOfStrings(after, "members")
		for _, m := range members {
			if isPipelineSA(m) {
				saMembers = append(saMembers, m)
			}
		}

		if len(saMembers) == 0 {
			continue
		}

		role := getStringVal(after, "role")
		if role == "" {
			continue
		}

		roleLower := strings.ToLower(role)

		if strings.Contains(roleLower, "*") {
			violations = append(violations, fmt.Sprintf("Wildcard role is not allowed for TFE/pipeline SA: %s in %s", role, rc.Address))
		}
		if roleLower == "roles/owner" {
			violations = append(violations, fmt.Sprintf("Overly broad role is not allowed for TFE/pipeline SA: roles/owner in %s", rc.Address))
		}
		if roleLower == "roles/editor" {
			violations = append(violations, fmt.Sprintf("Overly broad role is not allowed for TFE/pipeline SA: roles/editor in %s", rc.Address))
		}

		for _, prefix := range dataPlaneRolePrefixes {
			if strings.HasPrefix(roleLower, prefix) {
				violations = append(violations, fmt.Sprintf("Data-plane role is not allowed for TFE/pipeline SA: %s in %s", role, rc.Address))
			}
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("TFE pipeline service account violations: %v", violations)
	}
	return nil
}