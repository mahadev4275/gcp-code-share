# Security Audit Findings & Modular Test Suite Results

This document presents the compliance audit findings and test execution results for all Terraform modules across the repository, evaluated under **strict `deny` policy enforcement** against [tests/requirement.md](tests/requirement.md).

---

## Compliance Audit & Test Execution Table

| Module Directory | Primary Terraform Resources | Target Requirement IDs | Strict Policy Rules (`deny`) | Compliance Audit Result | Test Suite Status | Action Required / Failure Reason |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| [bq-cross-project-access](bq-cross-project-access) | `google_bigquery_dataset_iam_member` | `@CR.SECURITY.034`, `@CR.SECURITY.037` | Denies wildcard roles or public members (`allUsers`, `allAuthenticatedUsers`) | **COMPLIANT** | **PASS** | None. Explicit roles assigned; no wildcard or public bindings found. |
| [logbucket-bqlink](logbucket-bqlink) | `google_logging_project_bucket_config` | `@CR.SECURITY.009`, `@CR.SECURITY.037` | Denies logging buckets without `cmek_settings.kms_key_name` | **NON-COMPLIANT** | **FAIL** | Implementation team must add `cmek_settings` block to `google_logging_project_bucket_config`. |
| [terraform-log-router-bq](terraform-log-router-bq) | `google_bigquery_dataset`, `google_logging_project_sink` | `@CR.SECURITY.009`, `@CR.SECURITY.034` | Denies BigQuery datasets without `default_encryption_configuration.kms_key_name` | **NON-COMPLIANT** | **FAIL** | Implementation team must add `default_encryption_configuration` block to `google_bigquery_dataset`. |
| [terraform-bq-scheduled-query](terraform-bq-scheduled-query) | `google_service_account`, `google_bigquery_dataset_iam_member` | `@CR.SECURITY.034`, `@CR.SECURITY.035` | Denies wildcard action permissions or empty role assignments | **COMPLIANT** | **PASS** | None. Explicit data-plane roles used (`roles/bigquery.dataEditor`). |
| [terraform-cmek-policy](terraform-cmek-policy) | `google_org_policy_policy` | `@CR.SECURITY.009`, `@CR.ARCHITECTURE.001` | Denies empty allowed service lists on CMEK org policy | **COMPLIANT** | **PASS** | None. `gcp.restrictNonCmekServices` configured with allowed service list. |
| [terraform-org-policy](terraform-org-policy) | `google_org_policy_policy` | `@CR.ARCHITECTURE.001`, `@CR.SECURITY.009` | Denies empty location restriction lists | **COMPLIANT** | **PASS** | None. `gcp.resourceLocations` configured with valid location constraints. |
| [tf_for_scope](tf_for_scope) | `google_observability_trace_scope` | `@CR.ARCHITECTURE.001`, `@CR.SECURITY.002` | Denies empty resource scope lists | **COMPLIANT** | **PASS** | None. Trace scope resource names properly formatted. |
| [Trace_scope](Trace_scope) | Calls module `../tf_for_scope` | `@CR.ARCHITECTURE.001`, `@CR.SECURITY.002` | Denies trace scope creation failure | **COMPLIANT** | **PASS** | None. Submodule invocation configured with required variables. |

---

## Detailed Findings & Action Items for Implementation Team

### 1. `logbucket-bqlink`
* **Requirement**: `CR.SECURITY.009` (Data at Rest Encryption with CMEK).
* **Violation**: `google_logging_project_bucket_config.bucket` in [logbucket-bqlink/modules/log_analytics/main.tf](logbucket-bqlink/modules/log_analytics/main.tf) is missing `cmek_settings`.
* **Action Required**: Add a `cmek_settings { kms_key_name = ... }` block to `google_logging_project_bucket_config`.

### 2. `terraform-log-router-bq`
* **Requirement**: `CR.SECURITY.009` (Data at Rest Encryption with CMEK).
* **Violation**: `google_bigquery_dataset.logs` in [terraform-log-router-bq/main.tf](terraform-log-router-bq/main.tf) is missing `default_encryption_configuration`.
* **Action Required**: Add a `default_encryption_configuration { kms_key_name = ... }` block to `google_bigquery_dataset`.
