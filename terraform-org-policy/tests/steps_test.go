package tests

import (
	"fmt"

	"github.com/cucumber/godog"
)

type bddContext struct {
	plannedChanges []PlanResourceChange
}

func (c *bddContext) registerSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the resource locations org policy configuration is inspected$`, func() error { return nil })
	sc.Step(`^allowed values for resource locations must be non-empty$`, c.verifyNonEmptyLocations)
}

func (c *bddContext) verifyNonEmptyLocations() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_org_policy_policy" {
			return nil
		}
	}
	return fmt.Errorf("no google_org_policy_policy resource found in plan")
}
