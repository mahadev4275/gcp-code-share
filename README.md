# GCP Code Share

This repository contains Terraform configurations and validation tests (both static policy checking and runtime behavior verification) to ensure compliance and security of Google Cloud resources.

## Requirements

1. **Go 1.26+** (for executing test suites)
2. **Terraform 1.0+**
3. **Conftest** (for static policy evaluation)

---

## 1. Compliance Testing (OPA/Rego with Terratest)

Before deploying infrastructure, you can statically check your Terraform plan against security policies (e.g., ensuring resources are not made public) using Terratest and Rego.

### Running the Terratest Compliance Check
Run the specific test suite:
```bash
go test -v ./tests/ -run TestPublicAccessRegoPolicyWithTerratest
```

### Specifying Terraform Variables (.tfvars)
By default, the Terratest suite dynamically reads parameters from environment variables (`PROJECT_ID` / `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_REGION`). 

However, you can specify these variables using a `.tfvars` file:

1. **Auto-detection (Default Names):** 
   If you create `terraform.tfvars`, `terraform.tfvars.json`, `*.auto.tfvars`, or `*.auto.tfvars.json` in the `Trace_scope/` directory, the test runner will automatically detect and prioritize them.
   
2. **Custom Filename:**
   To specify a custom-named vars file, set the `TF_VAR_FILE` environment variable before running the test:
   ```bash
   export TF_VAR_FILE=/path/to/custom.tfvars
   go test -v ./tests/ -run TestPublicAccessRegoPolicyWithTerratest
   ```

---

## 2. Live GCP Runtime Audit (BDD with Godog)

To verify the active state of your deployed resources in your target GCP project:

### Pre-requisites
Make sure you have authenticated credentials with access to the target project (e.g., via `gcloud auth application-default login` or setting the `GOOGLE_APPLICATION_CREDENTIALS` environment variable).

### Running Feature Tests
Set the project ID environment variable and specify the BDD tag. Use `-run TestFeatures` to ensure that only the BDD suite runs (and skips the static Rego checks):
```bash
export PROJECT_ID=your_gcp_project_id
go test -v ./tests/ -run TestFeatures -godog.tags="@public_access"
```

Common tags include:
- `@public_access`: Verifies public access prevention, IAM rules, and VPC Service Controls.
- `@GA`: Checks if enabled GCP APIs are in General Availability (GA) status.
- `@obs_api`: Checks if the Cloud Observability API is enabled.
- `@cmek`: Audits Customer Managed Encryption Keys (CMEK) settings.
