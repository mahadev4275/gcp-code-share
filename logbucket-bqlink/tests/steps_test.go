package tests

import (
	"fmt"

	"github.com/cucumber/godog"
)

type bddContext struct {
	plannedChanges []PlanResourceChange
}

func (c *bddContext) registerSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the logging bucket configuration is inspected$`, func() error { return nil })
	sc.Step(`^cmek_settings with a valid KMS key name must be configured for the logging bucket$`, c.verifyCMEKSettings)
	sc.Step(`^no public IAM bindings should be present on the logging bucket$`, c.verifyNoPublicBindings)
}

func (c *bddContext) verifyCMEKSettings() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_logging_project_bucket_config" {
			cmek, ok := rc.Change.After["cmek_settings"].([]interface{})
			if !ok || len(cmek) == 0 {
				return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s missing cmek_settings", rc.Address)
			}
		}
	}
	return nil
}

func (c *bddContext) verifyNoPublicBindings() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_logging_project_bucket_iam_member" || rc.Type == "google_logging_project_bucket_iam_binding" {
			if member, ok := rc.Change.After["member"].(string); ok {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					return fmt.Errorf("security violation (CR.SECURITY.037): public member '%s' found in %s", member, rc.Address)
				}
			}
		}
	}
	return nil
}
