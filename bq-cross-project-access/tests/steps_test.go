package tests

import (
	"fmt"
	"strings"

	"github.com/cucumber/godog"
)

type bddContext struct {
	t              *godog.ScenarioContext
	plannedChanges []PlanResourceChange
}

func (c *bddContext) registerSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the BigQuery dataset IAM member configuration is inspected$`, func() error { return nil })
	sc.Step(`^no wildcard permissions should be granted in IAM bindings$`, c.verifyNoWildcards)
	sc.Step(`^no public members like allUsers or allAuthenticatedUsers should be granted access$`, c.verifyNoPublicMembers)
}

func (c *bddContext) verifyNoWildcards() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_bigquery_dataset_iam_member" {
			if role, ok := rc.Change.After["role"].(string); ok && strings.Contains(role, "*") {
				return fmt.Errorf("security violation (CR.SECURITY.034): wildcard role '%s' found in %s", role, rc.Address)
			}
		}
	}
	return nil
}

func (c *bddContext) verifyNoPublicMembers() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_bigquery_dataset_iam_member" {
			if member, ok := rc.Change.After["member"].(string); ok {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					return fmt.Errorf("security violation (CR.SECURITY.037): public member '%s' found in %s", member, rc.Address)
				}
			}
		}
	}
	return nil
}
