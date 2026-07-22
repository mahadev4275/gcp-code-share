package tests

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cucumber/godog"
)

type memberRoleAssignment struct {
	Address      string
	ResourceType string
	Role         string
}

// controlPlaneRoleKeywords identify predefined (vendor-managed) roles that grant
// control-plane write actions (CREATE/UPDATE/DELETE). Read-only roles such as
// *.viewer are intentionally excluded because they do not modify resource state.
var controlPlaneRoleKeywords = []string{
	"admin",
	"editor",
	"writer",
	"creator",
	"deleter",
	"updater",
	"manager",
}

// alwaysBroadPredefinedRoles are basic (primitive) predefined roles that always
// span control-plane actions and must never be used regardless of service.
var alwaysBroadPredefinedRoles = []string{
	"roles/owner",
	"roles/editor",
}

// vaultKeyManagementForbiddenRoles are vendor-managed roles that Vault service
// accounts must not use for key rotation/management. Custom roles with explicit
// key-management permissions must be used instead.
var vaultKeyManagementForbiddenRoles = []string{
	"roles/iam.serviceaccountadmin",
	"roles/iam.serviceaccountkeyadmin",
	"roles/cloudkms.admin",
	"roles/owner",
	"roles/editor",
}

// Package-level regexes for role classification. Names are unique to this file.
var (
	// Predefined (vendor-managed) roles are referenced as roles/<service>.<name>.
	predefinedRoleRe = regexp.MustCompile(`^roles/[^/]+$`)
	// Custom roles are referenced by their full resource path.
	customRoleRe = regexp.MustCompile(`^(projects|organizations)/[^/]+/roles/[^/]+$`)
)

func (c *bddContext) registerCustomRolesForControlPlaneSteps(sc *godog.ScenarioContext) {
	sc.Step(`^no vendor-managed control-plane roles should be assigned to any resources$`, c.noVendorManagedControlPlaneRolesAssigned)
	sc.Step(`^service accounts must use custom roles instead of vendor-managed control-plane roles$`, c.serviceAccountsMustUseCustomRolesForControlPlane)
	sc.Step(`^Vault service accounts must use custom roles for key management$`, c.vaultSAsMustUseCustomRolesForKeyManagement)
	sc.Step(`^CI\/CD pipeline service accounts must use custom roles for deployment$`, c.cicdPipelineSAsMustUseCustomRolesForDeployment)
	sc.Step(`^custom role definitions must enumerate explicit permissions without wildcards$`, c.customRoleDefinitionsEnumerateExplicitPermissions)
}

func (c *bddContext) buildMemberRoleIndexForCustomRoles() map[string][]memberRoleAssignment {
	memberRoles := make(map[string][]memberRoleAssignment)
	for _, rc := range c.plannedChanges {
		if !isIAMResource(rc.Type) {
			continue
		}
		after := rc.Change.After
		if after == nil {
			continue
		}

		role := getStringVal(after, "role")
		if role == "" {
			continue
		}

		var members []string
		member := getStringVal(after, "member")
		if member != "" {
			members = append(members, member)
		}
		membersList := getSliceOfStrings(after, "members")
		members = append(members, membersList...)

		for _, m := range members {
			memberRoles[m] = append(memberRoles[m], memberRoleAssignment{
				Address:      rc.Address,
				ResourceType: rc.Type,
				Role:         role,
			})
		}
	}
	return memberRoles
}

func (c *bddContext) noVendorManagedControlPlaneRolesAssigned() error {
	var violations []string
	for _, rc := range c.plannedChanges {
		if !isIAMResource(rc.Type) {
			continue
		}
		after := rc.Change.After
		if after == nil {
			continue
		}
		role := getStringVal(after, "role")
		if role == "" {
			continue
		}
		if isVendorManagedControlPlaneRole(role) {
			violations = append(violations, fmt.Sprintf("Vendor-managed control-plane role %q must be replaced by a custom role (resource: %s)", role, rc.Address))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("vendor-managed control-plane role violations: %v", violations)
	}
	return nil
}

func (c *bddContext) serviceAccountsMustUseCustomRolesForControlPlane() error {
	var violations []string
	memberRoles := c.buildMemberRoleIndexForCustomRoles()
	for member, assignments := range memberRoles {
		if !strings.Contains(strings.ToLower(member), "serviceaccount:") {
			continue
		}
		for _, a := range assignments {
			if isVendorManagedControlPlaneRole(a.Role) {
				violations = append(violations, fmt.Sprintf("Service account %q must use a custom role instead of %q (resource: %s)", member, a.Role, a.Address))
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("service account control-plane role violations: %v", violations)
	}
	return nil
}

func (c *bddContext) vaultSAsMustUseCustomRolesForKeyManagement() error {
	var violations []string
	memberRoles := c.buildMemberRoleIndexForCustomRoles()
	for member, assignments := range memberRoles {
		if !strings.Contains(strings.ToLower(member), "vault") {
			continue
		}
		for _, a := range assignments {
			roleLower := strings.ToLower(strings.TrimSpace(a.Role))
			for _, forbidden := range vaultKeyManagementForbiddenRoles {
				if forbidden == roleLower {
					violations = append(violations, fmt.Sprintf("Vault SA %q must use a custom key-management role instead of %q (resource: %s)", member, a.Role, a.Address))
				}
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("Vault SA key-management violations: %v", violations)
	}
	return nil
}

func (c *bddContext) cicdPipelineSAsMustUseCustomRolesForDeployment() error {
	var violations []string
	memberRoles := c.buildMemberRoleIndexForCustomRoles()
	for member, assignments := range memberRoles {
		if !isPipelineSA(member) {
			continue
		}
		for _, a := range assignments {
			roleLower := strings.ToLower(strings.TrimSpace(a.Role))
			for _, broad := range alwaysBroadPredefinedRoles {
				if broad == roleLower {
					violations = append(violations, fmt.Sprintf("Pipeline SA %q must use a custom deployment role instead of %q (resource: %s)", member, a.Role, a.Address))
				}
			}
			if isVendorManagedControlPlaneRole(a.Role) {
				violations = append(violations, fmt.Sprintf("Pipeline SA %q must use a custom deployment role instead of vendor-managed %q (resource: %s)", member, a.Role, a.Address))
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("pipeline SA deployment role violations: %v", violations)
	}
	return nil
}

func (c *bddContext) customRoleDefinitionsEnumerateExplicitPermissions() error {
	var violations []string
	for _, rc := range c.plannedChanges {
		if rc.Type != "google_project_iam_custom_role" && rc.Type != "google_organization_iam_custom_role" {
			continue
		}
		after := rc.Change.After
		if after == nil {
			continue
		}
		perms := getSliceOfStrings(after, "permissions")
		if len(perms) == 0 {
			violations = append(violations, fmt.Sprintf("Custom role %s must enumerate explicit permissions", rc.Address))
			continue
		}
		for _, p := range perms {
			if strings.Contains(p, "*") {
				violations = append(violations, fmt.Sprintf("Custom role %s must not use wildcard permission %q", rc.Address, p))
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("custom role definition violations: %v", violations)
	}
	return nil
}

// isVendorManagedControlPlaneRole reports whether role is a predefined
// (CSP/vendor-managed) role that grants control-plane write actions. Custom
// roles and read-only predefined roles (e.g. *.viewer) return false.
func isVendorManagedControlPlaneRole(role string) bool {
	role = strings.TrimSpace(role)
	roleLower := strings.ToLower(role)

	if role == "" || strings.Contains(role, "${") ||
		strings.HasPrefix(role, "var.") || strings.HasPrefix(role, "local.") {
		return false
	}

	// Custom roles are explicitly allowed.
	if customRoleRe.MatchString(role) {
		return false
	}

	// Primitive roles/owner and roles/editor always span control-plane actions.
	for _, broad := range alwaysBroadPredefinedRoles {
		if roleLower == broad {
			return true
		}
	}

	// Data-plane roles (e.g. BigQuery data access) are not control-plane roles.
	if roleLower == "roles/bigquery.dataeditor" || roleLower == "roles/bigquery.dataviewer" {
		return false
	}

	// Only predefined roles (roles/<service>.<name>) are in scope beyond here.
	if !predefinedRoleRe.MatchString(role) {
		return false
	}

	// Inspect the trailing segment for control-plane (write) keywords.
	name := roleLower
	if idx := strings.LastIndex(roleLower, "."); idx != -1 {
		name = roleLower[idx+1:]
	}
	for _, keyword := range controlPlaneRoleKeywords {
		if strings.Contains(name, keyword) {
			return true
		}
	}

	return false
}

// isPipelineSA returns true when the IAM member string represents a service
// account associated with an automated pipeline or CI/CD system.
func isPipelineSA(member string) bool {
	lower := strings.ToLower(member)
	return strings.Contains(lower, "serviceaccount:") &&
		(strings.Contains(lower, "tfe") ||
			strings.Contains(lower, "pipeline") ||
			strings.Contains(lower, "cicd") ||
			strings.Contains(lower, "ci-cd") ||
			strings.Contains(lower, "deploy"))
}