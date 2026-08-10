package tests

import (
	"encoding/json"
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
			val, ok := rc.Change.After["cmek_settings"]
			if !ok || val == nil {
				// pretty-print the entire Change.After to help debug shape returned by plan
				if b, err := json.MarshalIndent(rc.Change.After, "", "  "); err == nil {
					return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s missing cmek_settings. Change.After:\n%s", rc.Address, string(b))
				}
				return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s missing cmek_settings. Change.After (raw): %#v", rc.Address, rc.Change.After)
			}

			var kms string

			switch v := val.(type) {
			case []interface{}:
				// common representation: a single-element list with a map inside
				if len(v) > 0 {
					if m, ok := v[0].(map[string]interface{}); ok {
						if ks, ok := m["kms_key_name"].(string); ok && ks != "" {
							kms = ks
						}
					}
				}
			case map[string]interface{}:
				// other representations may come through as a plain map
				if ks, ok := v["kms_key_name"].(string); ok && ks != "" {
					kms = ks
				}
			default:
				// unexpected type — include the raw value for debugging
				if b, err := json.MarshalIndent(val, "", "  "); err == nil {
					return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s has unexpected cmek_settings type %T. Value:\n%s", rc.Address, v, string(b))
				}
				return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s has unexpected cmek_settings type %T. Value (raw): %#v", rc.Address, v, val)
			}

			if kms == "" {
				// kmss missing or empty — show the cmek_settings value for debugging
				if b, err := json.MarshalIndent(val, "", "  "); err == nil {
					return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s cmek_settings.kms_key_name is empty or missing. cmek_settings:\n%s", rc.Address, string(b))
				}
				return fmt.Errorf("security violation (CR.SECURITY.009): logging bucket %s cmek_settings.kms_key_name is empty or missing. cmek_settings (raw): %#v", rc.Address, val)
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
