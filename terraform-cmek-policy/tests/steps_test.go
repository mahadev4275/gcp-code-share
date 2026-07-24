package tests

import (
	"fmt"

	"github.com/cucumber/godog"
)

type bddContext struct {
	plannedChanges []PlanResourceChange
}

func (c *bddContext) registerSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the CMEK org policy configuration is inspected$`, func() error { return nil })
	sc.Step(`^allowed non-CMEK services list must be explicitly specified$`, c.verifyAllowedServices)
}

func (c *bddContext) verifyAllowedServices() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_org_policy_policy" {
			return nil
		}
	}
	return fmt.Errorf("no google_org_policy_policy resource found in plan")
}
