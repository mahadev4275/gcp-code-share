package tests

import (
	"fmt"
	"strings"

	"github.com/cucumber/godog"
)

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

func (c *bddContext) registerSegregationOfDutiesSteps(sc *godog.ScenarioContext) {
	sc.Step(`^no principal should hold conflicting duties$`, c.noPrincipalShouldHoldConflictingDuties)
	sc.Step(`^pipeline service accounts must only have deployment permissions and no human governance roles$`, c.pipelineServiceAccountsDeploymentOnly)
	sc.Step(`^human principals must not hold pipeline deployment roles$`, c.humanPrincipalsNotHoldPipelineDeploymentRoles)
}

func (c *bddContext) buildMemberRoleIndexForSegregationOfDuties() map[string][]memberRoleAssignment {
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

func (c *bddContext) noPrincipalShouldHoldConflictingDuties() error {
	var violations []string
	memberRoles := c.buildMemberRoleIndexForSegregationOfDuties()
	for member, assignments := range memberRoles {
		var roles []string
		for _, a := range assignments {
			roles = append(roles, a.Role)
		}

		for _, pair := range sodConflictingPairs {
			hasSetA := roleMatchesAnyPrefix(roles, pair.SetA)
			hasSetB := roleMatchesAnyPrefix(roles, pair.SetB)
			if hasSetA && hasSetB {
				violations = append(violations, fmt.Sprintf("Principal %q holds conflicting duties (%s). Detected roles: %v", member, pair.Description, roles))
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("segregation of duties violations: %v", violations)
	}
	return nil
}

func (c *bddContext) pipelineServiceAccountsDeploymentOnly() error {
	var violations []string
	memberRoles := c.buildMemberRoleIndexForSegregationOfDuties()
	for member, assignments := range memberRoles {
		if !isPipelineSA(member) {
			continue
		}
		for _, a := range assignments {
			roleLower := strings.ToLower(a.Role)
			for _, prefix := range humanOnlyRolePrefixes {
				if strings.HasPrefix(roleLower, strings.ToLower(prefix)) {
					violations = append(violations, fmt.Sprintf("Pipeline SA %q holds human-operator role %q (resource: %s)", member, a.Role, a.Address))
				}
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("pipeline SA permission violations: %v", violations)
	}
	return nil
}

func (c *bddContext) humanPrincipalsNotHoldPipelineDeploymentRoles() error {
	var violations []string
	memberRoles := c.buildMemberRoleIndexForSegregationOfDuties()
	for member, assignments := range memberRoles {
		if !strings.HasPrefix(member, "user:") && !strings.HasPrefix(member, "group:") {
			continue
		}
		for _, a := range assignments {
			roleLower := strings.ToLower(a.Role)
			for _, prefix := range pipelineRolePrefixes {
				if strings.HasPrefix(roleLower, strings.ToLower(prefix)) {
					violations = append(violations, fmt.Sprintf("Human principal %q holds pipeline-only role %q (resource: %s)", member, a.Role, a.Address))
				}
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("human principal permission violations: %v", violations)
	}
	return nil
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