package tests

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"cloud.google.com/go/storage"
	"github.com/cucumber/godog"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"google.golang.org/api/iterator"
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
	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}
	defer storageClient.Close()

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create kms client: %w", err)
	}
	defer kmsClient.Close()

	it := storageClient.Buckets(ctx, c.projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}

		// Verify the bucket has a default KMS key configured
		if attrs.Encryption == nil || attrs.Encryption.DefaultKMSKeyName == "" {
			return fmt.Errorf("security violation: storage bucket %s is not using CMEK", attrs.Name)
		}

		// Use KMS client to verify the key exists and is enabled
		req := &kmspb.GetCryptoKeyRequest{
			Name: attrs.Encryption.DefaultKMSKeyName,
		}
		key, err := kmsClient.GetCryptoKey(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to verify KMS key %s for bucket %s: %w", attrs.Encryption.DefaultKMSKeyName, attrs.Name, err)
		}

		if key.Primary.State != kmspb.CryptoKeyVersion_ENABLED {
			return fmt.Errorf("KMS key %s is not in an ENABLED state", attrs.Encryption.DefaultKMSKeyName)
		}
	}
	return nil
}

func (c *bddContext) theLifecycleOfTheseKeysMustBeManagedByIaC() error {
	// Verify that the KMS key is present in the Terraform state/outputs
	// This ensures the key was created and managed by the same IaC pipeline
	val, err := terraform.OutputE(c.t, c.tfOpts, "kms_key_name")
	if err != nil || val == "" {
		return fmt.Errorf("KMS key is not found in Terraform outputs; it might not be managed by IaC")
	}

	fmt.Printf("Verified KMS key management via IaC: %s\n", val)
	return nil
}
