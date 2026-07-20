package tests

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// memberRoleAssignment ties a role string back to the resource that grants it.
type memberRoleAssignment struct {
	FilePath     string
	ResourceType string
	ResourceName string
	Role         string
}

// conflictingDutyPair describes two mutually-exclusive sets of role prefixes.
// Holding roles from both sets in the same principal is a segregation-of-duties
// violation.
type conflictingDutyPair struct {
	SetA        []string
	SetB        []string
	Description string
}

var sodConflictingPairs = []conflictingDutyPair{
	{
		// A single identity must not both deploy infrastructure and govern/approve it.
		SetA: []string{
			"roles/deploymentmanager",
			"roles/resourcemanager.projectcreator",
			"roles/resourcemanager.foldercreator",
			"roles/resourcemanager.projectdeleter",
			"roles/resourcemanager.folderadmin",
			"roles/resourcemanager.projectiamadmin",
			"roles/cloudbuild.builds.editor",
		},
		SetB: []string{
			"roles/iam.securityadmin",
			"roles/orgpolicy.policyadmin",
			"roles/accesscontextmanager.policyadmin",
			"roles/iam.securityreviewer",
		},
		Description: "infrastructure deployment and security governance/approval",
	},
	{
		// A single identity must not both administer encryption keys and consume them.
		SetA: []string{
			"roles/cloudkms.admin",
			"roles/cloudkms.cryptokeyadmin",
		},
		SetB: []string{
			"roles/cloudkms.cryptokeyencrypterdecrypter",
			"roles/cloudkms.cryptokeyencrypter",
			"roles/cloudkms.cryptokeydecrypter",
		},
		Description: "key management and key usage",
	},
}

// pipelineRolePrefixes are roles that are valid only for pipeline/deployment SAs.
// Human principals must not hold these.
var pipelineRolePrefixes = []string{
	"roles/deploymentmanager",
	"roles/resourcemanager.projectcreator",
	"roles/resourcemanager.folderadmin",
	"roles/cloudbuild",
	"roles/run.admin",
	"roles/container.admin",
	"roles/compute.admin",
	"roles/iam.serviceaccountuser",
	"roles/iam.serviceaccounttokencreator",
}

// humanOnlyRolePrefixes are governance/review roles inappropriate for automated
// pipeline service accounts.
var humanOnlyRolePrefixes = []string{
	"roles/iam.securityadmin",
	"roles/iam.securityreviewer",
	"roles/orgpolicy.policyadmin",
	"roles/accesscontextmanager",
	"roles/billing.admin",
	"roles/billing.viewer",
	"roles/resourcemanager.organizationadmin",
}

// Package-level compiled regexes used by SOD helpers.
var (
	singleMemberRe = regexp.MustCompile(`(?m)^\s*member\s*=\s*"([^"]+)"`)
	listMemberRe   = regexp.MustCompile(`(?s)members\s*=\s*\[([^\]]+)\]`)
	quotedValueRe  = regexp.MustCompile(`"([^"]+)"`)
	roleLineRe     = regexp.MustCompile(`(?m)^\s*role\s*=\s*"([^"]+)"`)
)

func TestSegregationOfDuties(t *testing.T) {
	t.Parallel()

	repoRoot := "../.."
	resources, err := collectTerraformResources(repoRoot)
	assert.NoError(t, err)

	iamResources := filterIAMResources(resources)

	// Build a member → role index once and reuse across sub-tests.
	memberRoles := buildMemberRoleIndex(iamResources)

	t.Run("No Conflicting Duties Per Principal", func(t *testing.T) {
		// Ensure no single principal accumulates roles from both sides of any
		// conflicting-duty pair. Terraform variable references that cannot be
		// statically resolved are skipped (see addMemberToSet).
		for member, assignments := range memberRoles {
			var roles []string
			for _, a := range assignments {
				roles = append(roles, a.Role)
			}

			for _, pair := range sodConflictingPairs {
				hasSetA := roleMatchesAnyPrefix(roles, pair.SetA)
				hasSetB := roleMatchesAnyPrefix(roles, pair.SetB)
				assert.Falsef(t, hasSetA && hasSetB,
					"Principal %q holds conflicting duties (%s). Detected roles: %v",
					member, pair.Description, roles)
			}
		}
	})

	t.Run("Pipeline SA Has Deployment Permissions Only", func(t *testing.T) {
		// Pipeline/CI-CD service accounts must not hold human-operator
		// governance or review roles.
		for member, assignments := range memberRoles {
			if !isPipelineSA(member) {
				continue
			}
			for _, a := range assignments {
				roleLower := strings.ToLower(a.Role)
				for _, prefix := range humanOnlyRolePrefixes {
					assert.Falsef(t, strings.HasPrefix(roleLower, prefix),
						"Pipeline SA %q holds human-operator role %q which is not allowed (file: %s, resource: %s.%s)",
						member, a.Role, a.FilePath, a.ResourceType, a.ResourceName)
				}
			}
		}
	})

	t.Run("Human Principals Do Not Hold Pipeline Deployment Roles", func(t *testing.T) {
		// Human user: and group: principals must not accumulate automated
		// pipeline deployment capabilities.
		for member, assignments := range memberRoles {
			if !strings.HasPrefix(member, "user:") && !strings.HasPrefix(member, "group:") {
				continue
			}
			for _, a := range assignments {
				roleLower := strings.ToLower(a.Role)
				for _, prefix := range pipelineRolePrefixes {
					assert.Falsef(t, strings.HasPrefix(roleLower, prefix),
						"Human principal %q holds pipeline-only role %q (file: %s, resource: %s.%s)",
						member, a.Role, a.FilePath, a.ResourceType, a.ResourceName)
				}
			}
		}
	})
}

// buildMemberRoleIndex returns a map keyed by IAM member identity string.
// Each value is the slice of role assignments made to that member across all
// resources in the provided list. Terraform-interpolated or variable-reference
// member strings are skipped because they cannot be statically resolved.
func buildMemberRoleIndex(resources []tfResource) map[string][]memberRoleAssignment {
	index := make(map[string][]memberRoleAssignment)

	for _, r := range resources {
		roleMatches := roleLineRe.FindAllStringSubmatch(r.Body, -1)
		members := extractAllMembersFromBody(r.Body)

		for _, rm := range roleMatches {
			if len(rm) < 2 {
				continue
			}
			role := strings.TrimSpace(rm[1])
			for _, member := range members {
				index[member] = append(index[member], memberRoleAssignment{
					FilePath:     r.FilePath,
					ResourceType: r.Type,
					ResourceName: r.Name,
					Role:         role,
				})
			}
		}
	}

	return index
}

// extractAllMembersFromBody returns all unique, statically-known member/principal
// strings found in a Terraform resource body, handling both the singular
// `member = "..."` and plural `members = [...]` attribute forms.
func extractAllMembersFromBody(body string) []string {
	var members []string
	seen := make(map[string]struct{})

	// Singular form: member = "serviceAccount:..."
	for _, m := range singleMemberRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			addMemberToSet(&members, seen, m[1])
		}
	}

	// Plural form: members = ["serviceAccount:...", "user:..."]
	for _, m := range listMemberRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			for _, qm := range quotedValueRe.FindAllStringSubmatch(m[1], -1) {
				if len(qm) > 1 {
					addMemberToSet(&members, seen, qm[1])
				}
			}
		}
	}

	return members
}

// addMemberToSet appends v to members if it has not been seen before and is
// a resolvable static literal (not a Terraform variable or interpolation).
func addMemberToSet(members *[]string, seen map[string]struct{}, v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	// Skip Terraform expressions that cannot be resolved statically.
	if strings.Contains(v, "${") || strings.HasPrefix(v, "var.") || strings.HasPrefix(v, "local.") {
		return
	}
	if _, exists := seen[v]; !exists {
		seen[v] = struct{}{}
		*members = append(*members, v)
	}
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

// roleMatchesAnyPrefix returns true when at least one role in the slice has a
// case-insensitive prefix match against any string in prefixes.
func roleMatchesAnyPrefix(roles []string, prefixes []string) bool {
	for _, role := range roles {
		roleLower := strings.ToLower(role)
		for _, prefix := range prefixes {
			if strings.HasPrefix(roleLower, strings.ToLower(prefix)) {
				return true
			}
		}
	}
	return false
}