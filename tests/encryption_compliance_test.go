package tests

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cucumber/godog"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"google.golang.org/api/iterator"
)

// ---------------------------------------------------------------------------
// Constants and approved-value sets
// ---------------------------------------------------------------------------

// approvedSymmetricAlgorithms are the only algorithms accepted for data-at-rest
// encryption keys under the Key Management Standard.
var approvedSymmetricAlgorithms = map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]bool{
	kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION: true, // AES-256-GCM
}

// approvedHSMProtectionLevels lists the protection levels that satisfy FIPS 140-2
// Level 3 requirements for production data-at-rest encryption.
var approvedHSMProtectionLevels = map[kmspb.ProtectionLevel]bool{
	kmspb.ProtectionLevel_HSM: true, // Cloud HSM — FIPS 140-2 Level 3
}

// maxRotationPeriod is the maximum allowed time between automatic key rotations.
const maxRotationPeriod = 365 * 24 * time.Hour // 365 days

// tlsValidationHost is the GCP API endpoint used to probe TLS compliance.
const tlsValidationHost = "cloudkms.googleapis.com"

// ---------------------------------------------------------------------------
// BDD Godog Step Registrations (for encryption_compliance.feature)
// ---------------------------------------------------------------------------

// registerEncryptionComplianceSteps hooks the feature file steps to Go functions
func (c *bddContext) registerEncryptionComplianceSteps(sc *godog.ScenarioContext) {
	// Scenario: Approved cryptographic algorithms
	sc.Step(`^the KMS key ring and crypto keys are provisioned$`, func() error { return nil })
	sc.Step(`^the cryptographic algorithm configuration is inspected$`, func() error { return nil })
	sc.Step(`^all symmetric keys must use AES-256-GCM$`, c.verifyApprovedAlgorithms)
	sc.Step(`^no non-approved algorithms must be present$`, c.verifyNoUnapprovedAlgorithms)

	// Scenario: Minimum bit strength
	sc.Step(`^the key bit strength is inspected$`, func() error { return nil })
	sc.Step(`^all symmetric keys must have a minimum strength of 256 bits$`, c.verifyMinimumBitStrength)

	// Scenario: FIPS 140-2 Level 3 — CloudHSM-backed keys
	sc.Step(`^the key protection level is inspected$`, func() error { return nil })
	sc.Step(`^all production data-at-rest keys must use CloudHSM protection level$`, c.verifyCloudHSMProtectionLevel)
	sc.Step(`^the CloudHSM module must meet FIPS 140-2 Level 3 certification$`, c.verifyFIPS1402Level3)

	// Scenario: Key rotation schedules
	sc.Step(`^the key rotation configuration is inspected$`, func() error { return nil })
	sc.Step(`^automatic key rotation must be enabled$`, c.verifyAutomaticRotationEnabled)
	sc.Step(`^the rotation period must not exceed 365 days$`, c.verifyRotationPeriodCompliance)
	sc.Step(`^the next rotation time must be scheduled$`, c.verifyNextRotationScheduled)

	// Scenario: TLS 1.2+ for data-in-transit
	sc.Step(`^the encryption-in-transit posture is validated against the key management standard$`, func() error { return nil })
	sc.Step(`^all KMS API endpoints must enforce TLS 1\.2 or higher$`, c.verifyKMSEndpointTLS)
	sc.Step(`^legacy TLS versions must be rejected by KMS endpoints$`, c.verifyKMSEndpointLegacyRejected)

	// Scenario: Key lifecycle management via IaC
	sc.Step(`^key resources are provisioned through Infrastructure as Code$`, func() error { return nil })
	sc.Step(`^KMS key rings must be present in the Terraform state$`, c.verifyKeyRingInTerraformState)
	sc.Step(`^KMS crypto keys must be present in the Terraform state$`, c.verifyCryptoKeyInTerraformState)
	sc.Step(`^organization policies for CMEK must be enforced via IaC$`, c.verifyOrgPolicyCMEKInTerraformState)
}

// ---------------------------------------------------------------------------
// Step handler functions
// ---------------------------------------------------------------------------

// listProjectCryptoKeyVersions enumerates all CryptoKeyVersions across all
// key rings in the configured project and location.
func (c *bddContext) listProjectCryptoKeyVersions() ([]*kmspb.CryptoKeyVersion, error) {
	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}
	defer kmsClient.Close()

	location := resolveLocation()
	parent := fmt.Sprintf("projects/%s/locations/%s", c.projectID, location)

	var allVersions []*kmspb.CryptoKeyVersion

	// List all key rings
	krIter := kmsClient.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: parent})
	for {
		kr, err := krIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list key rings: %w", err)
		}

		// List all crypto keys in the key ring
		ckIter := kmsClient.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: kr.Name})
		for {
			ck, err := ckIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to list crypto keys in %s: %w", kr.Name, err)
			}

			// List all versions of each crypto key
			vIter := kmsClient.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: ck.Name})
			for {
				v, err := vIter.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					return nil, fmt.Errorf("failed to list key versions in %s: %w", ck.Name, err)
				}
				// Only evaluate enabled or primary versions
				if v.State == kmspb.CryptoKeyVersion_ENABLED ||
					v.State == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_STATE_UNSPECIFIED {
					allVersions = append(allVersions, v)
				}
			}
		}
	}
	return allVersions, nil
}

// listProjectCryptoKeys enumerates all CryptoKeys across all key rings.
func (c *bddContext) listProjectCryptoKeys() ([]*kmspb.CryptoKey, error) {
	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}
	defer kmsClient.Close()

	location := resolveLocation()
	parent := fmt.Sprintf("projects/%s/locations/%s", c.projectID, location)

	var allKeys []*kmspb.CryptoKey

	krIter := kmsClient.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: parent})
	for {
		kr, err := krIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list key rings: %w", err)
		}

		ckIter := kmsClient.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: kr.Name})
		for {
			ck, err := ckIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to list crypto keys in %s: %w", kr.Name, err)
			}
			allKeys = append(allKeys, ck)
		}
	}
	return allKeys, nil
}

// --- Algorithm compliance ---

func (c *bddContext) verifyApprovedAlgorithms() error {
	versions, err := c.listProjectCryptoKeyVersions()
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return nil // no keys provisioned — nothing to validate
	}

	var violations []string
	for _, v := range versions {
		if v.Algorithm == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
			continue // skip unspecified (Google-managed default)
		}
		if !approvedSymmetricAlgorithms[v.Algorithm] {
			violations = append(violations,
				fmt.Sprintf("key version %s uses non-approved algorithm %s", v.Name, v.Algorithm))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("approved algorithm violations:\n  %s", strings.Join(violations, "\n  "))
	}
	return nil
}

func (c *bddContext) verifyNoUnapprovedAlgorithms() error {
	// Delegated to the same check as verifyApprovedAlgorithms — any non-approved
	// algorithm found will surface as a violation.
	return c.verifyApprovedAlgorithms()
}

// --- Minimum bit strength ---

func (c *bddContext) verifyMinimumBitStrength() error {
	versions, err := c.listProjectCryptoKeyVersions()
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return nil
	}

	var violations []string
	for _, v := range versions {
		// GOOGLE_SYMMETRIC_ENCRYPTION is AES-256-GCM (256-bit).
		// Any asymmetric or other key type is checked by algorithm approval.
		if v.Algorithm == kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION {
			continue // 256-bit — compliant
		}
		if v.Algorithm == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
			continue // Google-managed default — 256-bit AES
		}
		// Non-symmetric algorithms must still meet bit-strength requirements
		// but the standard mandates symmetric AES-256 for data-at-rest,
		// so anything else is already flagged by the algorithm check.
		violations = append(violations,
			fmt.Sprintf("key version %s algorithm %s may not meet 256-bit symmetric minimum", v.Name, v.Algorithm))
	}
	if len(violations) > 0 {
		return fmt.Errorf("minimum bit strength violations:\n  %s", strings.Join(violations, "\n  "))
	}
	return nil
}

// --- FIPS 140-2 Level 3 (CloudHSM) ---

func (c *bddContext) verifyCloudHSMProtectionLevel() error {
	versions, err := c.listProjectCryptoKeyVersions()
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return nil
	}

	var violations []string
	for _, v := range versions {
		if !approvedHSMProtectionLevels[v.ProtectionLevel] {
			violations = append(violations,
				fmt.Sprintf("key version %s protection_level=%s (expected HSM for FIPS 140-2 Level 3)", v.Name, v.ProtectionLevel))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("CloudHSM protection level violations:\n  %s", strings.Join(violations, "\n  "))
	}
	return nil
}

func (c *bddContext) verifyFIPS1402Level3() error {
	// Cloud HSM keys in GCP are backed by Marvell LiquidSecurity HSMs that
	// hold FIPS 140-2 Level 3 certification. Verifying protection_level=HSM
	// is sufficient to assert FIPS 140-2 Level 3 compliance.
	return c.verifyCloudHSMProtectionLevel()
}

// --- Key rotation ---

func (c *bddContext) verifyAutomaticRotationEnabled() error {
	keys, err := c.listProjectCryptoKeys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}

	var violations []string
	for _, k := range keys {
		if k.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
			continue // rotation only applies to symmetric encrypt/decrypt keys
		}
		if k.RotationSchedule == nil {
			violations = append(violations,
				fmt.Sprintf("crypto key %s does not have automatic rotation configured", k.Name))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("automatic rotation violations:\n  %s", strings.Join(violations, "\n  "))
	}
	return nil
}

func (c *bddContext) verifyRotationPeriodCompliance() error {
	keys, err := c.listProjectCryptoKeys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}

	var violations []string
	for _, k := range keys {
		if k.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
			continue
		}
		schedule, ok := k.RotationSchedule.(*kmspb.CryptoKey_RotationPeriod)
		if !ok || schedule == nil || schedule.RotationPeriod == nil {
			violations = append(violations,
				fmt.Sprintf("crypto key %s has no rotation period set", k.Name))
			continue
		}
		period := schedule.RotationPeriod.AsDuration()
		if period > maxRotationPeriod {
			violations = append(violations,
				fmt.Sprintf("crypto key %s rotation_period=%s exceeds max %s", k.Name, period, maxRotationPeriod))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("rotation period violations:\n  %s", strings.Join(violations, "\n  "))
	}
	return nil
}

func (c *bddContext) verifyNextRotationScheduled() error {
	keys, err := c.listProjectCryptoKeys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}

	var violations []string
	for _, k := range keys {
		if k.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
			continue
		}
		if k.NextRotationTime == nil {
			violations = append(violations,
				fmt.Sprintf("crypto key %s does not have a next rotation time scheduled", k.Name))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("next rotation schedule violations:\n  %s", strings.Join(violations, "\n  "))
	}
	return nil
}

// --- TLS 1.2+ enforcement on KMS endpoints ---

func (c *bddContext) verifyKMSEndpointTLS() error {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", tlsValidationHost+":443",
		&tls.Config{MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		return fmt.Errorf("failed to establish TLS 1.2+ connection to %s: %w", tlsValidationHost, err)
	}
	defer conn.Close()

	if conn.ConnectionState().Version < tls.VersionTLS12 {
		return fmt.Errorf("KMS endpoint negotiated TLS 0x%04x which is below TLS 1.2", conn.ConnectionState().Version)
	}
	return nil
}

func (c *bddContext) verifyKMSEndpointLegacyRejected() error {
	for _, ver := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp", tlsValidationHost+":443",
			&tls.Config{MinVersion: ver, MaxVersion: ver},
		)
		if err == nil {
			conn.Close()
			return fmt.Errorf("KMS endpoint accepted legacy TLS version 0x%04x — must reject", ver)
		}
	}
	return nil
}

// --- Key lifecycle management via IaC ---

func (c *bddContext) verifyKeyRingInTerraformState() error {
	if c.tfOpts == nil {
		return fmt.Errorf("terraform options not configured — cannot inspect state")
	}
	val, err := terraform.OutputE(c.t, c.tfOpts, "kms_key_ring_name")
	if err != nil || val == "" {
		return fmt.Errorf("KMS key ring not found in Terraform outputs — key ring must be managed via IaC")
	}
	return nil
}

func (c *bddContext) verifyCryptoKeyInTerraformState() error {
	if c.tfOpts == nil {
		return fmt.Errorf("terraform options not configured — cannot inspect state")
	}
	val, err := terraform.OutputE(c.t, c.tfOpts, "kms_crypto_key_name")
	if err != nil || val == "" {
		return fmt.Errorf("KMS crypto key not found in Terraform outputs — crypto key must be managed via IaC")
	}
	return nil
}

func (c *bddContext) verifyOrgPolicyCMEKInTerraformState() error {
	if c.tfOpts == nil {
		return fmt.Errorf("terraform options not configured — cannot inspect state")
	}
	// Check for org policy constraint output that enforces CMEK
	val, err := terraform.OutputE(c.t, c.tfOpts, "cmek_org_policy_enforced")
	if err != nil || val == "" {
		return fmt.Errorf("CMEK organization policy not found in Terraform outputs — org policy must be managed via IaC")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func resolveLocation() string {
	for _, k := range []string{"GOOGLE_CLOUD_REGION", "KMS_LOCATION"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return "us-central1"
}
