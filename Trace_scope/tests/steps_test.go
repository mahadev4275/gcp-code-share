package tests

import (
	"fmt"

	"github.com/cucumber/godog"
)

type bddContext struct {
	plannedChanges []PlanResourceChange
}

func (c *bddContext) registerSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the trace scope wrapper module configuration is inspected$`, func() error { return nil })
	sc.Step(`^the trace scope resource should be planned for creation$`, c.verifyTraceScopePlanned)
}

func (c *bddContext) verifyTraceScopePlanned() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_observability_trace_scope" {
			return nil
		}
	}
	return fmt.Errorf("no google_observability_trace_scope resource found in plan")
}
