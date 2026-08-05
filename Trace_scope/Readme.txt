=====================================================
Google Cloud Observability Trace Scope - Terraform
=====================================================

Overview
========
This Terraform configuration creates and manages a Google Cloud
Observability Trace Scope. A Trace Scope enables centralized tracing
across multiple Google Cloud projects, allowing distributed traces
to be viewed and analyzed from a single observability scope.

The solution is implemented using a reusable Terraform module and
can be extended to monitor additional projects as required.

Repository Structure
====================

Trace_scope/
│
├── main.tf
├── provider.tf
├── variable.tf
├── variables.tfvars
├── terraform.tfstate
├── terraform.tfstate.backup
│
└── modules/
    └── tf_for_scope/
        ├── main.tf
        ├── variable.tf
        └── output.tf

Components
==========

Root Module
-----------
The root module is responsible for:

1. Loading provider configuration.
2. Reading input variables.
3. Calling the reusable Trace Scope module.

Example:

module "trace_scope" {
  source   = "./modules/tf_for_scope"

  location = var.location
  project  = var.project
  projects = var.projects
  region   = var.region
}

Child Module (tf_for_scope)
---------------------------
The child module creates the Trace Scope resource:

Resource:
google_observability_trace_scope

Key Configuration:

- Trace Scope ID: test_scope
- Location: Provided via Terraform variable
- Resource Names: Generated from the monitored project list
- Description:
  "A trace scope configured with Terraform"

Example Resource:

resource "google_observability_trace_scope" "observability_trace_scope" {
  trace_scope_id = "test_scope"
  location       = var.location

  resource_names = [
    for project_id in var.monitored_projects :
    "projects/${project_id}"
  ]

  description = "A trace scope configured with Terraform"
}

Input Variables
===============

location
---------
Description:
Google Cloud location where the Trace Scope will be created.

Example:
location = "global"

project
-----------------
Description:
Hosting project used for Terraform operations.

Example:
project = "example-host-project"

monitored_projects
-----------------------------
Description:
List of Google Cloud projects to be monitored within the Trace Scope.

Example:

projects = [
  "project-a",
  "project-b",
  "project-c"
]


Deployment Steps
================

1. Initialize Terraform

   terraform init

2. Validate Configuration

   terraform validate

3. Review Planned Changes

   terraform plan

4. Deploy Resources

   terraform apply

5. Verify Trace Scope Creation

   terraform state list

Expected Outcome
================

After successful deployment:

- A Google Cloud Observability Trace Scope is created.
- Multiple projects are associated with the scope.
- Distributed traces can be viewed centrally.
- Teams can analyze application traces across projects from a
  unified observability experience.

Use Case
========

This solution is useful for organizations that:

- Run applications across multiple GCP projects.
- Require centralized trace monitoring.
- Need unified observability for microservices.
- Want infrastructure managed through Terraform.

Notes
=====

- Ensure the Google Cloud provider has the required permissions.
- Verify that the Observability and Cloud Trace APIs are enabled.
- Update the monitored project list whenever new projects need
  to be included in the Trace Scope.
- Terraform state should be stored securely for production
  environments.

Author: Burhan Ashraf

