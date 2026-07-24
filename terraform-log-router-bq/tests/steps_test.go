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
	sc.Step(`^the BigQuery log router dataset configuration is inspected$`, func() error { return nil })
	sc.Step(`^the Log Sink writer identity IAM binding is inspected$`, func() error { return nil })
	sc.Step(`^default_encryption_configuration with KMS key name should be configured$`, c.verifyEncryptionConfigured)
	sc.Step(`^no wildcard permissions should be granted to the sink writer identity$`, c.verifyNoWildcards)
}

func (c *bddContext) verifyEncryptionConfigured() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_bigquery_dataset" {
			enc, ok := rc.Change.After["default_encryption_configuration"].([]interface{})
			if !ok || len(enc) == 0 {
				return fmt.Errorf("security violation (CR.SECURITY.009): BigQuery dataset %s missing default_encryption_configuration", rc.Address)
			}
		}
	}
	return nil
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
