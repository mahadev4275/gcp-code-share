# GCP Code Share

This repository contains Terraform configurations and validation tests (both static policy checking and runtime behavior verification) to ensure compliance and security of Google Cloud resources.

## Requirements

1. **Go 1.26+** (for executing test suites)
2. **Terraform 1.0+**
3. **Conftest** (for static OPA/Rego policy evaluation)

## Setup Persistent Binaries

```bash
mkdir -p $HOME/bin
# Set your desired Terraform version
TF_VERSION="1.9.5"

# Download and extract to $HOME/bin
curl -sL "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip" -o /tmp/terraform.zip
unzip -o /tmp/terraform.zip -d $HOME/bin/
rm /tmp/terraform.zip

# Verify installation
terraform --version

# Set your desired Conftest version
CONFTEST_VERSION="0.54.0"

# Download and extract to $HOME/bin
curl -sL "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" -o /tmp/conftest.tar.gz
tar -xzf /tmp/conftest.tar.gz -C $HOME/bin/ conftest
rm /tmp/conftest.tar.gz

# Verify installation
conftest --version
```

---

## Dual-Suite BDD Test Architecture (Godog + Terratest)

The BDD test suite automatically discovers all Terraform modules in subdirectories across the repository and supports two distinct execution paths selected via `-godog.tags`:

### Performance & Setup Strategy
* **Dynamic Module Discovery**: Automatically scans and detects all Terraform module subdirectories in the project.
* **Cached Static Plans**: Static plan evaluation (`@opa`) runs across all discovered modules using a `sync.Once` cache, completing in **~14 seconds** without deploying live GCP infrastructure.
* **One-Time Live Setup/Teardown**: When running live scenarios (`@live`), infrastructure across all discovered Terraform modules is provisioned **once per test run** (rather than per scenario) and cleanly destroyed upon suite completion.

### Controlling Terraform CLI Output & Logging
By default, verbose Terraform CLI logs (`terraform init`, `plan`, `apply`, `destroy`) are suppressed so that Godog Gherkin scenarios and pass/fail summaries are displayed cleanly.

You can control Terraform logging per test run via CLI flag or environment variable:

* **Default (Quiet Mode - Clean Godog Output)**:
  ```bash
  go test -v ./tests/ -godog.tags="@opa and ~@live"
  ```
* **Verbose Mode (View Full Terraform CLI Output for Debugging)**:
  - **Via CLI flag**:
    ```bash
    go test -v ./tests/ -godog.tags="@opa and ~@live" -tf.quiet=false
    ```
  - **Via environment variable**:
    ```bash
    TF_QUIET=false go test -v ./tests/ -run TestFeatures -godog.tags="@live"
    ```

### 1. Static Policy-as-Code & OPA Suite (`@opa`)

Evaluates Terraform plan JSON outputs offline against OPA/Rego rules (`policies/`), Conftest checks, custom role constraints, segregation of duties, and insecure URL scheme scanning (`http://`, `ws://`, `ftp://`, `telnet://`). 

* **Requires $0 GCP resources and no cloud API calls.**
* **Uses static plan evaluation completing in ~5 seconds.**
* **Filtering with `~@live` explicitly prevents `terraform apply` live infrastructure provisioning hooks from running.**

```bash
go test -v ./tests/ -godog.tags="@opa and ~@live"
```

#### Feature Tags in `@opa`:
* `@cmek`: Validates Customer Managed Encryption Keys (CMEK) and KMS key rotation lifecycle policies via OPA Rego rules (`policies/cmek_policy.rego`).
* `@public_access`: Verifies Storage/Log bucket IAM public access restrictions, Storage Public Access Prevention Org Policies, and VPC-SC Cloud Logging perimeters via Rego rules (`policies/public_access.rego`).
* `@encryption_in_transit`: Enforces TLS 1.2+, Load Balancer SSL policies (`MODERN`/`RESTRICTED`), Cloud SQL SSL options (`require_ssl=true`, TLS 1.2+), Cloud Run ingress restrictions, and scans planned resource attributes for insecure URL schemes.
* `@segregation_of_duties`: Enforces segregation of duties in IAM bindings and pipeline service account restrictions.
* `@custom_roles`: Verifies custom role definitions and ensures no vendor-managed control plane roles are assigned to service accounts.

---

### 2. Live GCP Infrastructure Integration Suite (`@live`)

Provisions live Terraform infrastructure (`terraform apply`) across all discovered repository modules **once per test run**, validates active resource behavior and policies against live Google Cloud APIs, and cleans up resources (`terraform destroy`).

```bash
export PROJECT_ID=your_gcp_project_id
go test -v ./tests/ -run TestFeatures -godog.tags="@live"
```

#### Feature Tags in `@live`:
* `@iam_restrictions`: Enforces wildcard limits, conditional trust boundary scoping, and folder/project scoped service account bindings.
* `@GA`: Verifies all enabled GCP APIs in the project are in General Availability (GA) status.
* `@obs_api`: Checks Cloud Observability / Trace API enablement state.
* `@encryption_compliance`: Audits KMS key ring, cryptographic algorithm (AES-256-GCM), key bit strength (256-bit), CloudHSM protection levels, and key rotation.

---

## Additional Compliance Testing (OPA/Rego with Terratest)

Run individual static Terratest compliance checks directly:

```bash
go test -v ./tests/ -run TestPublicAccessRegoPolicyWithTerratest
```

### Specifying Terraform Variables (.tfvars)
By default, the test suite dynamically reads parameters from environment variables (`PROJECT_ID` / `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_REGION`). 

To specify custom `.tfvars`:
1. **Auto-detection (Default Names):** Place `terraform.tfvars`, `terraform.tfvars.json`, `*.auto.tfvars`, or `*.auto.tfvars.json` in module directories.
2. **Custom Filename:** Set `TF_VAR_FILE` before running:
   ```bash
   export TF_VAR_FILE=/path/to/custom.tfvars
   go test -v ./tests/ -run TestPublicAccessRegoPolicyWithTerratest
   ```
