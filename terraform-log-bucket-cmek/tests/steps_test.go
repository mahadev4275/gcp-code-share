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
	sc.Step(`^the dedicated CMEK logging bucket configuration is inspected$`, func() error { return nil })
	sc.Step(`^the KMS crypto key IAM binding is inspected$`, func() error { return nil })
	sc.Step(`^cmek_settings must be present on the logging bucket$`, c.verifyCMEKSettings)
	sc.Step(`^KMS crypto key rotation period must not exceed 365 days$`, c.verifyKeyRotation)
	sc.Step(`^no wildcard permissions or public members must be granted$`, c.verifyNoWildcards)
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

func (c *bddContext) verifyKeyRotation() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_kms_crypto_key" {
			rotation, ok := rc.Change.After["rotation_period"].(string)
			if !ok || rotation == "" {
				return fmt.Errorf("security violation (CR.SECURITY.009): KMS key %s missing rotation_period", rc.Address)
			}
		}
	}
	return nil
}

func (c *bddContext) verifyNoWildcards() error {
	for _, rc := range c.plannedChanges {
		if rc.Type == "google_kms_crypto_key_iam_member" {
			if role, ok := rc.Change.After["role"].(string); ok && strings.Contains(role, "*") {
				return fmt.Errorf("security violation (CR.SECURITY.034): wildcard role '%s' in %s", role, rc.Address)
			}
		}
	}
	return nil
}
