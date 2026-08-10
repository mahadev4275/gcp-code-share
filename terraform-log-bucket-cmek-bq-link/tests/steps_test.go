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
		// Accept both resource types that can represent the logging bucket in different plans
		if rc.Type != "google_logging_project_bucket_config" && rc.Type != "google_logging_project_bucket" {
			continue
		}

		val, ok := rc.Change.After["cmek_settings"]
		if !ok || val == nil {
			return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s missing cmek_settings", rc.Address)
		}

		checkMap := func(m map[string]interface{}) bool {
			if ks, ok := m["kms_key_name"].(string); ok && ks != "" {
				return true
			}
			if kv, ok := m["kms_key_version_name"].(string); ok && kv != "" {
				return true
			}
			return false
		}

		found := false
		switch v := val.(type) {
		case []interface{}:
			// common representation: a single-element list holding a map
			if len(v) > 0 {
				if m, ok := v[0].(map[string]interface{}); ok {
					found = checkMap(m)
				}
			}
		case map[string]interface{}:
			// some TF/provider/plan shapes use a plain map
			found = checkMap(v)
		default:
			return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s has unexpected cmek_settings type %T", rc.Address, val)
		}

		if !found {
			return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s cmek_settings missing kms_key_name or kms_key_version_name", rc.Address)
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
