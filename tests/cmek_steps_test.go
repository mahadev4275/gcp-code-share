package tests

import (
	"fmt"

	"github.com/cucumber/godog"
)

// registerCMEKPolicySteps hooks the feature file steps to Go functions
func (c *bddContext) registerCMEKPolicySteps(sc *godog.ScenarioContext) {
	sc.Step(`^the scope is limited to the infrastructure layer$`, func() error { return nil })
	sc.Step(`^the encryption requirement is for symmetric encryption of data at rest$`, func() error { return nil })
	sc.Step(`^resources are provisioned using standard Terraform modules$`, func() error { return nil })
	sc.Step(`^the deployment is managed through Infrastructure as Code \(IaC\) pipelines$`, func() error { return nil })
	sc.Step(`^the data must be encrypted using Customer Managed Encryption Keys \(CMEK\/BYOK\)$`, c.theDataMustBeEncryptedUsingCMEK)
	sc.Step(`^the lifecycle of these keys must be managed by the same IaC pipelines$`, c.theLifecycleOfTheseKeysMustBeManagedByIaC)
}

func (c *bddContext) theDataMustBeEncryptedUsingCMEK() error {
	return c.runConftestAgainstMasterComposition()
}

func (c *bddContext) theLifecycleOfTheseKeysMustBeManagedByIaC() error {
	if c.projectID == "" {
		return fmt.Errorf("GCP Project ID is not configured")
	}

	needsCMEK := false
	hasKMS := false

	for _, rc := range c.plannedChanges {
		if rc.Type == "google_kms_crypto_key" || rc.Type == "google_kms_key_ring" {
			hasKMS = true
		}
		// List of resources that store data at rest (matching the Rego policy)
		if rc.Type == "google_storage_bucket" || rc.Type == "google_bigquery_dataset" ||
			rc.Type == "google_bigquery_table" || rc.Type == "google_logging_project_bucket_config" ||
			rc.Type == "google_pubsub_topic" || rc.Type == "google_sql_database_instance" ||
			rc.Type == "google_compute_disk" {
			needsCMEK = true
		}
	}

	if needsCMEK && !hasKMS {
		return fmt.Errorf("security policy violation: data-at-rest resources are provisioned but no KMS key rings (google_kms_key_ring) or crypto keys (google_kms_crypto_key) found in IaC planned changes for project %s", c.projectID)
	}

	return nil
}
