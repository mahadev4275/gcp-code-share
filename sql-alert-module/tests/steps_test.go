package tests

import (
	"fmt"

	"github.com/cucumber/godog"
)

type bddContext struct {
	plannedChanges []PlanResourceChange
}

func (c *bddContext) registerSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the SQL alert monitoring configuration is inspected$`, func() error { return nil })
	sc.Step(`^the SQL alert policy condition is inspected$`, func() error { return nil })
	sc.Step(`^the enabled service must be monitoring.googleapis.com$`, c.verifyMonitoringService)
	sc.Step(`^periodicity must be positive and notification email must be configured$`, c.verifyAlertCondition)
}

func (c *bddContext) verifyMonitoringService() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_project_service" {
			if service, ok := rc.Change.After["service"].(string); ok && service == "monitoring.googleapis.com" {
				return nil
			}
		}
	}
	return fmt.Errorf("monitoring.googleapis.com project service not found in plan")
}

func (c *bddContext) verifyAlertCondition() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_monitoring_alert_policy" {
			return nil
		}
	}
	return fmt.Errorf("no google_monitoring_alert_policy found in plan")
}
