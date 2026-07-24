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

## Modular Per-Module Test Architecture

Each Terraform module in the project root has its own dedicated, isolated `tests/` directory containing:
* **Tailored BDD Features (`.feature`)**: Scenarios mapped directly to Requirement IDs from [tests/requirement.md](tests/requirement.md) (e.g. `@CR.SECURITY.009`, `@CR.SECURITY.034`, `@CR.SECURITY.037`, `@CR.ARCHITECTURE.001`).
* **Tailored Rego Policies (`policies/*.rego`)**: Policy-as-code rules targeting the specific resources defined by the module.
* **Isolated Test Runners (`bdd_test.go`, `plan_helper.go`)**: Runs static plan generation (`terraform plan -out=tfplan`) and Conftest policy evaluation against only that module.

### Module Test Directory Structure
```
<module_name>/
  └── tests/
      ├── bdd_test.go
      ├── plan_helper.go
      ├── steps_test.go
      ├── features/
      │   └── <module_name>.feature
      └── policies/
          └── <module_name>_policy.rego
```

---

## Controlling Output Logging (Quiet vs Verbose Mode)

By default, verbose Terraform CLI output (`terraform init`, `plan`, `show`) is suppressed (`-tf.quiet=true`) so that Godog BDD scenario steps and pass/fail statistics are displayed cleanly.

* **Default (Quiet Mode - Clean Godog Output)**:
  ```bash
  go test -v ./bq-cross-project-access/tests/...
  ```

* **Verbose Mode (View Full Terraform CLI Output for Debugging)**:
  - **Via CLI flag**:
    ```bash
    go test -v ./bq-cross-project-access/tests/... -tf.quiet=false
    ```
  - **Via environment variable**:
    ```bash
    TF_QUIET=false go test -v ./...
    ```

---

## Running Tests

### 1. Testing an Individual Module (Independent & Fast)
To test a single Terraform module in isolation without affecting or deploying other modules:

```bash
# Test BigQuery Cross-Project Access module
go test -v ./bq-cross-project-access/tests/...

# Test Logging Bucket BigQuery Link module
go test -v ./logbucket-bqlink/tests/...

# Test Monitoring SQL Alert module
go test -v ./sql-alert-module/tests/...

# Test Scheduled Query module
go test -v ./terraform-bq-scheduled-query/tests/...

# Test CMEK Org Policy module
go test -v ./terraform-cmek-policy/tests/...

# Test Dedicated CMEK Log Bucket module
go test -v ./terraform-log-bucket-cmek/tests/...

# Test Log Router BigQuery Sink module
go test -v ./terraform-log-router-bq/tests/...

# Test Resource Locations Org Policy module
go test -v ./terraform-org-policy/tests/...

# Test Observability Trace Scope module
go test -v ./tf_for_scope/tests/...

# Test Trace Scope Wrapper module
go test -v ./Trace_scope/tests/...
```

### 2. Testing All Modules Concurrently across Repository
To run tests for all modules across the repository:

```bash
go test -v ./...
```
