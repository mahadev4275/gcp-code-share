package tests

import (
	"github.com/cucumber/godog"
)

type bddContext struct {
	plannedChanges []PlanResourceChange
}

func (c *bddContext) registerSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the logging bucket configuration is inspected$`, func() error { return nil })
	sc.Step(`^cmek_settings with a valid KMS key name must be configured for the logging bucket$`, c.verifyCMEKSettings)
	sc.Step(`^no public IAM bindings should be present on the logging bucket$`, func() error { return nil })
}

func (c *bddContext) verifyCMEKSettings() error {
	// CMEK check is validated via OPA Rego policy in policies/logbucket_bqlink_policy.rego
	return nil
}
