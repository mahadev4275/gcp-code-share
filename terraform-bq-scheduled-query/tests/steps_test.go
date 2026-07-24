package tests

import (
	"fmt"
	"strings"

	"github.com/cucumber/godog"
)

type bddContext struct {
	plannedChanges []PlanResourceChange
}

func (c *bddContext) registerSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the scheduled query configuration is inspected$`, func() error { return nil })
	sc.Step(`^the scheduled query service account IAM binding is inspected$`, func() error { return nil })
	sc.Step(`^no wildcard action permissions should be assigned to the scheduled query service account$`, c.verifyNoWildcards)
	sc.Step(`^the role assigned must be specific and explicitly defined$`, c.verifyExplicitRoles)
}

func (c *bddContext) verifyNoWildcards() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_bigquery_dataset_iam_member" {
			if role, ok := rc.Change.After["role"].(string); ok && strings.Contains(role, "*") {
				return fmt.Errorf("security violation (CR.SECURITY.034): wildcard role '%s' in %s", role, rc.Address)
			}
		}
	}
	return nil
}

func (c *bddContext) verifyExplicitRoles() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_bigquery_dataset_iam_member" {
			if role, ok := rc.Change.After["role"].(string); ok && role == "" {
				return fmt.Errorf("security violation (CR.SECURITY.035): empty role in %s", rc.Address)
			}
		}
	}
	return nil
}
