package tests

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestCustomRolesForControlPlane(t *testing.T) {
	t.Parallel()

	// Load plan changes
	changes, err := getRepositoryPlanChanges(t)
	assert.NoError(t, err)

	// Build a member -> roles index for easy querying
	memberRoles := make(map[string][]memberRoleAssignment)
	for _, rc := range changes {
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

	t.Run("No Vendor-Managed Roles For Control-Plane", func(t *testing.T) {
		for _, rc := range changes {
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
			assert.Falsef(t, isVendorManagedControlPlaneRole(role),
				"Vendor-managed control-plane role %q must be replaced by a custom role (resource: %s)",
				role, rc.Address)
		}
	})

	t.Run("Service Accounts Use Custom Roles For Control-Plane", func(t *testing.T) {
		for member, assignments := range memberRoles {
			if !strings.Contains(strings.ToLower(member), "serviceaccount:") {
				continue
			}
			for _, a := range assignments {
				if !isVendorManagedControlPlaneRole(a.Role) {
					continue
				}
				assert.Failf(t, "Service account uses vendor-managed control-plane role",
					"Service account %q must use a custom role instead of %q (resource: %s)",
					member, a.Role, a.Address)
			}
		}
	})

	t.Run("Vault SAs Use Custom Roles For Key Management", func(t *testing.T) {
		for member, assignments := range memberRoles {
			if !strings.Contains(strings.ToLower(member), "vault") {
				continue
			}
			for _, a := range assignments {
				roleLower := strings.ToLower(strings.TrimSpace(a.Role))
				for _, forbidden := range vaultKeyManagementForbiddenRoles {
					assert.NotEqualf(t, forbidden, roleLower,
						"Vault SA %q must use a custom key-management role instead of %q (resource: %s)",
						member, a.Role, a.Address)
				}
			}
		}
	})

	t.Run("CICD Pipeline SA Uses Custom Role For Deployment", func(t *testing.T) {
		for member, assignments := range memberRoles {
			if !isPipelineSA(member) {
				continue
			}
			for _, a := range assignments {
				roleLower := strings.ToLower(strings.TrimSpace(a.Role))
				for _, broad := range alwaysBroadPredefinedRoles {
					assert.NotEqualf(t, broad, roleLower,
						"Pipeline SA %q must use a custom deployment role instead of %q (resource: %s)",
						member, a.Role, a.Address)
				}
				assert.Falsef(t, isVendorManagedControlPlaneRole(a.Role),
					"Pipeline SA %q must use a custom deployment role instead of vendor-managed %q (resource: %s)",
					member, a.Role, a.Address)
			}
		}
	})

	t.Run("Custom Role Definitions Enumerate Explicit Permissions", func(t *testing.T) {
		for _, rc := range changes {
			if rc.Type != "google_project_iam_custom_role" && rc.Type != "google_organization_iam_custom_role" {
				continue
			}
			after := rc.Change.After
			if after == nil {
				continue
			}
			perms := getSliceOfStrings(after, "permissions")
			assert.NotEmptyf(t, perms,
				"Custom role %s must enumerate explicit permissions", rc.Address)
			for _, p := range perms {
				assert.NotContainsf(t, p, "*",
					"Custom role %s must not use wildcard permission %q", rc.Address, p)
			}
		}
	})
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