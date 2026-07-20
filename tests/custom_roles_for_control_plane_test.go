package tests

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

// Package-level regexes for role classification. Names are unique to this file
// to avoid clashing with declarations in SECURITY_IF_008 / SECURITY_IF_009.
var (
	// Predefined (vendor-managed) roles are referenced as roles/<service>.<name>.
	predefinedRoleRe = regexp.MustCompile(`^roles/[^/]+$`)
	// Custom roles are referenced by their full resource path.
	customRoleRe = regexp.MustCompile(`^(projects|organizations)/[^/]+/roles/[^/]+$`)
	// Match custom-role definition resources so their permissions can be audited.
	customRoleDefRe = regexp.MustCompile(`(?i)_iam_custom_role$`)
	// permissions = [ ... ] block inside a custom role definition.
	customRolePermsRe = regexp.MustCompile(`(?s)permissions\s*=\s*\[([^\]]*)\]`)
)

func TestCustomRolesForControlPlane(t *testing.T) {
	t.Parallel()

	repoRoot := "../.."
	resources, err := collectTerraformResources(repoRoot)
	assert.NoError(t, err)

	iamResources := filterIAMResources(resources)

	// Reuse the member → role index builder from SECURITY_IF_009.
	memberRoles := buildMemberRoleIndex(iamResources)

	t.Run("No Vendor-Managed Roles For Control-Plane", func(t *testing.T) {
		// Any IAM binding that grants a predefined control-plane role is a
		// violation; a custom role with enumerated permissions must be used.
		for _, r := range iamResources {
			for _, match := range roleLineRe.FindAllStringSubmatch(r.Body, -1) {
				if len(match) < 2 {
					continue
				}
				role := strings.TrimSpace(match[1])
				assert.Falsef(t, isVendorManagedControlPlaneRole(role),
					"Vendor-managed control-plane role %q must be replaced by a custom role (file: %s, resource: %s.%s)",
					role, r.FilePath, r.Type, r.Name)
			}
		}
	})

	t.Run("Service Accounts Use Custom Roles For Control-Plane", func(t *testing.T) {
		// Service-account principals that receive control-plane access must be
		// granted custom roles, never vendor-managed admin/editor/owner roles.
		for member, assignments := range memberRoles {
			if !strings.Contains(strings.ToLower(member), "serviceaccount:") {
				continue
			}
			for _, a := range assignments {
				if !isVendorManagedControlPlaneRole(a.Role) {
					continue
				}
				assert.Failf(t, "Service account uses vendor-managed control-plane role",
					"Service account %q must use a custom role instead of %q (file: %s, resource: %s.%s)",
					member, a.Role, a.FilePath, a.ResourceType, a.ResourceName)
			}
		}
	})

	t.Run("Vault SAs Use Custom Roles For Key Management", func(t *testing.T) {
		// HashiCorp Vault service accounts must rotate/manage keys via a custom
		// role, not vendor-managed serviceAccountAdmin/KMS-admin roles.
		for member, assignments := range memberRoles {
			if !isVaultSA(member) {
				continue
			}
			for _, a := range assignments {
				roleLower := strings.ToLower(strings.TrimSpace(a.Role))
				for _, forbidden := range vaultKeyManagementForbiddenRoles {
					assert.NotEqualf(t, forbidden, roleLower,
						"Vault SA %q must use a custom key-management role instead of %q (file: %s, resource: %s.%s)",
						member, a.Role, a.FilePath, a.ResourceType, a.ResourceName)
				}
			}
		}
	})

	t.Run("CICD Pipeline SA Uses Custom Role For Deployment", func(t *testing.T) {
		// CI/CD pipeline service accounts must deploy via a custom role and must
		// never be granted the primitive roles/editor or roles/owner.
		for member, assignments := range memberRoles {
			if !isPipelineSA(member) {
				continue
			}
			for _, a := range assignments {
				roleLower := strings.ToLower(strings.TrimSpace(a.Role))
				for _, broad := range alwaysBroadPredefinedRoles {
					assert.NotEqualf(t, broad, roleLower,
						"Pipeline SA %q must use a custom deployment role instead of %q (file: %s, resource: %s.%s)",
						member, a.Role, a.FilePath, a.ResourceType, a.ResourceName)
				}
				assert.Falsef(t, isVendorManagedControlPlaneRole(a.Role),
					"Pipeline SA %q must use a custom deployment role instead of vendor-managed %q (file: %s, resource: %s.%s)",
					member, a.Role, a.FilePath, a.ResourceType, a.ResourceName)
			}
		}
	})

	t.Run("Custom Role Definitions Enumerate Explicit Permissions", func(t *testing.T) {
		// Where custom roles are defined, they must enumerate explicit
		// permissions and must not use wildcards, preserving least privilege.
		for _, r := range resources {
			if !customRoleDefRe.MatchString(strings.ToLower(r.Type)) {
				continue
			}

			perms := extractCustomRolePermissions(r.Body)
			assert.NotEmptyf(t, perms,
				"Custom role %s.%s must enumerate explicit permissions (file: %s)",
				r.Type, r.Name, r.FilePath)

			for _, p := range perms {
				assert.NotContainsf(t, p, "*",
					"Custom role %s.%s must not use wildcard permission %q (file: %s)",
					r.Type, r.Name, p, r.FilePath)
			}
		}
	})
}

// isVendorManagedControlPlaneRole reports whether role is a predefined
// (CSP/vendor-managed) role that grants control-plane write actions. Custom
// roles (projects/.../roles/..., organizations/.../roles/...) and read-only
// predefined roles (e.g. *.viewer) return false.
func isVendorManagedControlPlaneRole(role string) bool {
	role = strings.TrimSpace(role)
	roleLower := strings.ToLower(role)

	// Terraform expressions cannot be resolved statically; do not flag them.
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

// isVaultSA reports whether the IAM member string represents a HashiCorp Vault
// service account.
func isVaultSA(member string) bool {
	lower := strings.ToLower(member)
	return strings.Contains(lower, "serviceaccount:") && strings.Contains(lower, "vault")
}

// extractCustomRolePermissions returns the individual permission strings declared
// in a custom-role definition body.
func extractCustomRolePermissions(body string) []string {
	var perms []string

	m := customRolePermsRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return perms
	}

	for _, qm := range quotedValueRe.FindAllStringSubmatch(m[1], -1) {
		if len(qm) > 1 {
			v := strings.TrimSpace(qm[1])
			if v != "" {
				perms = append(perms, v)
			}
		}
	}

	return perms
}