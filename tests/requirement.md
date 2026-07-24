CR.Architecture 001

CR.ARCHITECTURE.001 - Only GA (General Availability) CSP services and their associated APIs should be used in a production (controlled) environment.

Required to leave Sandbox
Required to leave St
Domain: SERVICE ARCHITECTURE

Description
This guideline enforces the use of stable and fully supported services in the production environment. By restricting tenant access to GA services, potential risks and instability associated with pre-release software are mitigated.
- Ensure that new services/capabilities achieve General Availability (GA) status before releasing them for tenant use in production.

Reference
- ARCH.001 - Use Only GA Services in Controlled Environment: Only GA (General Availability) CSP services should be used in a production (controlled) environment.

Test Requirements
CR.ARCHITECTURE.001.TR01
GIVEN the need for a new CSP service/capability
WHEN a new service or one of its capabilities is being engineered
THEN the CSP service, or its enhanced API, should be in GA (General Availability) status from the CSP before it can be used in a Production/Controlled environment

CR.SECURITY.009
Data at rest must be encrypted by keys under the organization's control (CPEK, BYOK) and not be out of compliance with the organization's Key and Certificate Management Standard

All data at rest must be encrypted using Customer-Managed Encryption Keys (CMEK) or Bring Your Own Key (BYOK) where required by the organization's Data Protection Status and Key and Certificate Standard. The ability to fully manage data via CMEK/BYOK is necessary for the organization to maintain both ownership and control of data regardless of hosting location. This applies to data hosted in a public cloud whether it is hosted by the organization or by a third party on behalf of the organization. All data at rest must comply with the organization's CSP Data Protection Standard as well as the Key and Certificate Management Standard and the organization's Cryptography Standard to prevent unauthorized leakage. Only CloudHSM-backed CMEKs (FIPS 140-2 Level 3) are approved in the organization's environments. Keys must be managed via IaC pipelines using the standard Terraform module. Default provider-managed keys are not permitted for data at rest unless the Customer Key/Certificate Management functionality is unavailable.

Feature: Data at Rest Encryption with CMEK

Scenario: Storage service uses CMEK with HSM protection
Given a storage service exists in an environment
And the service stores data classified above Public
When the encryption configuration is inspected
Then encryption type must be Customer-Managed Key (CMEK)
And the key must be from Cloud KMS with HSM protection level (FIPS 140-2 Level 3)
And automatic key rotation must be enabled

Feature: CMEK Enforcement on Write
Scenario: Write request without CMEK is denied
Given a storage service has a resource policy applied
When a write request is made without specifying CMEK encryption
Then the request must be denied
And the denial must be logged to audit logs

Feature: Organization Policy HSM Enforcement
Scenario: Org-level policy to prevent
Given a GCP project is in scope
When constraints/cloudkms.allowedProtectionLevels is queried
Then only "HSM" must be permitted
And SOFTWARE-backed key creation must be denied and logged

CR.SECURITY.002
Data in transit or movement must be encrypted and not be out of compliance with the organization's Key and Certificate Management Standard

All data in transit must be encrypted across service-to-service, external, and hybrid communication channels and not be out of compliance with the organization's Key and Certificate Management Standard. TLS 1.2 (TLS 1.3 recommended) is required for all HTTPS connections. Legacy protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) must be disabled. Encryption applies to both north-south (external) and east-west (internal) traffic, including API calls, inter-region transfers, and cloud-to-on-premises communications. Load balancers, API Gateways, and Cloud Functions must be configured with SSL/TLS policies that reject legacy protocols. Service-to-service communication must use encrypted protocols (TLS/mTLS) enforced via service mesh or VPC encryption. Organization-issued certificates from an approved Certificate Authority must be used. Unencrypted traffic must be blocked and violations logged to Cloud Audit Logs.

Feature: Encryption in Transit Enforcement

Scenario: Service enforces TLS 1.2 or higher
Given a service exists in an environment
When the encryption-in-transit configuration is inspected
Then HTTPS or TLS must be in use
And TLS version must be 1.2 or higher
And legacy protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) must be disabled

Feature: Service-to-Service Encryption

Scenario: Internal communication uses TLS/mTLS
Given a service transmits data to another service
When the communication channel is validated
Then data transmission must use TLS or mTLS
And unencrypted traffic must be blocked
And encryption events must be captured in audit logs

Feature: Load Balancer TLS Policy Compliance

Scenario: Load Balancer enforces modern TLS configuration
Given a Load Balancer or API Gateway exists
When the SSL/TLS policy configuration is inspected
Then the SSL policy profile must be set to MODERN or RESTRICTED
And the minimum TLS version must be TLS 1.2
And legacy cipher suites must be explicitly disabled

Feature: Database TLS Enforcement

Scenario: Database requires TLS for all connections
Given a managed database instance exists
When the database SSL/TLS configuration is inspected
Then SSL/TLS must be required for all client connections
And connections without valid TLS certificates must be rejected
And the minimum TLS version must be 1.2

---
id: "CR.SECURITY.009"
redline: "Encryption must not be out of compliance with the organization's Key Management Standard"
status: "active"
environments:
  - "Sandbox"
  - "Service Engineering"
domain: "Data Protection"
data_classification: "All"
description: |
  All encryption implementations must comply with the organization's Key Management Standard (KMS), covering
  data at rest and data in transit. Compliance areas include key rotation schedules, approved
  cryptographic algorithms (AES-256-GCM, TLS 1.2+), minimum bit strength (256-bit symmetric),
  FIPS 140-2 Level 3 for production data at rest (CloudHSM-backed CMEKs), and full key lifecycle
  management via approved IaC pipelines and Organization Policies.
sa_principle:
  - "SA.6 - Secure by Design"
  - "SA.11 - Prevent Data Leakage"
  - "SA.12 - Protect Production Environment and Data"
policy_standard:
  - name: "Information Systems Security Standard (CISS)"
    sections:
      - "9.2.3.1 - Cryptographic Controls Implementation"
      - "9.2.3 - Key Management Requirements"
      - "9.2.5 - Cryptographic Algorithms Standards"
  - name: "Key Management Standard (KMS)"
    sections:
      - "3.1.1 - Application Managers must catalog cryptographic tool use in CSI"
      - "3.1.1 - Keys must not be used for multiple purposes"
      - "3.3.3 - Private and symmetric keys must not be shared between environments"
      - "3.4.2 - Key Values must not be displayed in clear text"
      - "3.6.5 - Audit logs must capture functional changes to key stores"
      - "3.7 - Ad-Hoc Rotation - Compromised keys must be marked and removed"
      - "3.8.1 - Keystores and keys must be backed up or archived"
      - "3.9.1 - Key Deregistration and Destruction requirements"
  - name: "Approved Security Protocols and Cryptographic Algorithms Standard (ASPCAS)"
    sections:
      - "Algorithm and bit strength requirements"
      - "TLS/SSL Protocol Requirements - Minimum TLS 1.2"
      - "Cipher Suite Specifications"
mitre_reference:
  - "T1600: Weaken Encryption"
  - "TA0010: Exfiltration"
  - "T1486: Data Encrypted for Impact"
control_patterns:
  - csp: "gcp"
    description: |
      **Data at Rest:**
      All CMEKs must be CloudHSM-backed (FIPS 140-2 Level 3) using AES-256-GCM with a 365-day
      rotation period. Keys must not be shared across environments. Production keys must have
      prevent_destroy=true and a 30-day destroy schedule.

      **Data in Transit:**
      All HTTPS endpoints must enforce TLS 1.2 or higher with approved cipher suites (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305). Load Balancers must use MODERN or RESTRICTED
      SSL/TLS policy profiles. Legacy protocols must be disabled. GKE service-to-service must use mTLS.
  - csp: "aws"
    description: |
      **Data at Rest:**
      All KMS CMKs must use AES-256-GCM with automatic annual rotation. Keys must not be shared
      across environments. Key deletion must have a minimum 30-day waiting period.

      **Data in Transit:**
      All HTTPS endpoints must enforce TLS 1.2 or higher with approved cipher suites. ALB/NLB
      security policies must use modern TLS configurations. Legacy protocols must be disabled.
test_requirement:
  - id: "CR.SECURITY.009-TR-01"
    description: "Verify encryption key is compliant with Key Management Standards"
    gherkin: |
      Feature: Key Management Compliance

        Scenario: Encryption key meets KMS requirements
          Given an encryption key exists for a service in an environment
          When the key configuration is inspected
          Then key_protection_level must be "HSM" (FIPS 140-2 Level 3)
          And algorithm must be AES-256
          And rotation_period must be 365 days or less
          And the key must not be shared with any other environment
  - id: "CR.SECURITY.009-TR-02"
    description: "Verify encryption in transit uses approved protocols and cipher suites"
    gherkin: |
      Feature: Encryption in Transit Compliance

        Scenario: Service enforces approved TLS configuration
          Given a service transmits data in an environment
          When the TLS configuration is inspected
          Then TLS version must be 1.2 or higher
          And cipher suites must be from approved list (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305)
          And legacy protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) must be disabled
          And violations must be logged to audit logs

---
id: "CR.SECURITY.034"
redline: "Principal permissions must be narrowly scoped to the minimum required access with explicit enumeration and contextual conditions"
status: "active"
environments:
  - "Sandbox"
  - "Service Engineering"
domain: "Identity and Access Management (IAM)"
data_classification: "All"
description: |
  Principal permissions must be least-privileged, explicitly enumerated, and
  narrowly scoped to the required resource boundary.

  Wildcard action grants are prohibited in ALLOW statements.
  Conditions must constrain access where supported (for example network, time,
  and resource attributes).

  Permission grants must be documented, justified, and reviewed at least quarterly.
  Continuous analysis must detect and remediate over-permissioned principals.
IaC pipeline identities may hold broader control-plane permissions only when documented,
justified, wildcard-free. Data-plane access is prohibited.
sa_principle:
  - "SA.9 - Least Privilege"
policy_standard:
  - name: "Identity and Access Management (IAM) Standard (DOC-1244)"
    sections:
      - "3.1.1.1.a - User IDs: minimum access required (least privilege)"
      - "3.2.1.1.a - Functional IDs: minimum access required (least privilege)"
      - "3.3.1.1.a - Shared IDs: minimum access required (least privilege)"
      - "3.4.1.1.a - System IDs: minimum access required (least privilege)"
  - name: "Global IAM (GIAM) Standard"
    sections:
      - "Least Privilege: all principals granted minimum permissions required for function"
      - "Custom Role Enforcement: predefined/vendor-managed roles prohibited for control-plane"
      - "Periodic Access Review: minimum quarterly review of all permission grants"
mitre_reference:
  - "TA0004: Privilege Escalation"
  - "T1098: Account Manipulation"
  - "T1078: Valid Accounts"
  - "TA0003: Persistence"
control_patterns:
  - csp: "gcp"
    description: |
      Enforce explicit permissions and conditional scoping via policy-as-code.
      Reject wildcard actions in ALLOW statements.
      Continuously detect over-privileged principals and remediate.
  - csp: "aws"
    description: |
      Use customer-managed IAM policies with explicit Action lists and resource ARN scoping.
      Apply contextual conditions such as aws:RequestedRegion, aws:PrincipalOrgID,
      aws:ResourceTag, and aws:SourceVpc.
      Use Access Analyzer to identify and remediate over-permissioned policies.
  - csp: "gcp"
    description: |
      Use custom IAM roles with explicit permissions and lowest-scope bindings.
      Apply IAM Conditions to constrain access by resource, time, or context.
      Use IAM Recommender and Policy Analyzer for least-privilege remediation.
test_requirement:
  - id: "CR.SECURITY.034-TR-01"
    description: "Verify no wildcard permissions are used in ALLOW statements"
    gherkin: |
      GIVEN an IAM ALLOW policy, role, or binding is configured
      WHEN permitted actions are evaluated
      THEN wildcard action grants are not present
      AND each allowed action is explicitly enumerated
  - id: "CR.SECURITY.034-TR-02"
    description: "Verify permissions are conditionally scoped at the trust boundary"
    gherkin: |
      GIVEN a principal permission binding is configured
      WHEN binding scope and conditions are evaluated
      THEN permissions are constrained by supported conditions
      AND permissions are granted only at the minimum required trust boundary
  - id: "CR.SECURITY.034-TR-03"
    description: "Verify service identity bindings are scoped to minimum required resource scope"
    gherkin: |
      GIVEN a service identity requires cloud access
      WHEN IAM bindings are reviewed
      THEN bindings are scoped to minimum required resource boundaries
      AND cross-environment access is prevented unless explicitly justified
  - id: "CR.SECURITY.034-TR-04"
    description: "Verify IaC pipeline identity has no wildcard or data-plane permissions"
    gherkin: |
      GIVEN an IaC pipeline identity is configured
      WHEN effective permissions are reviewed
      THEN permissions are control-plane only
      AND wildcard and data-plane permissions are not present
      AND broader access is documented, justified, and reviewed quarterly

---
id: "CR.SECURITY.035"
redline: "For control-plane actions vendor managed roles must not be used"
status: "active"
environments:
  - "Sandbox"
  - "Service Engineering"
domain: "Identity and Access Management (IAM)"
data_classification: "All"
description: |
  For control-plane actions (methods), vendor-managed roles (i.e., CSP predefined roles
  such as GCP's roles/editor, roles/owner, roles/viewer and service-specific admin roles)
  must not be used. Control-plane actions include CREATE, UPDATE, and DELETE operations
  that modify the configuration or state of GCP resources.

  Instead, custom IAM roles are created with explicitly enumerated permissions that
  grant only minimum required access. This improves least-privilege enforcement,
  auditability, and blast-radius reduction.
sa_principle:
  - "SA.9 - Least Privilege"
policy_standard:
  - name: "Identity and Access Management (IAM) Standard (DOC-1244)"
    sections:
      - "3.4.1.1 - System IDs: vendor-managed roles must not be used for control-plane actions"
mitre_reference:
  - "T1098.003: Additional Cloud Roles"
  - "T1098: Privilege Escalation"
  - "T1078: Valid Accounts"
  - "TA0008: Defense Evasion"
control_patterns:
  - csp: "gcp"
    description: |
      **Custom IAM Roles:**
      Use project-scoped custom IAM roles with explicit permission enumeration for
      control-plane actions and minimal required permissions.

      **Service-Specific Roles:**
      Use service-specific custom roles for GCS, BigQuery, Compute Engine, and Cloud SQL
      with control-plane and data-plane permission separation.

      **Vault Service Accounts:**
      Use narrowly scoped custom roles for Vault service accounts to support key
      management without broad vendor-admin role assignment.

      **CI/CD Pipeline:**
      Use CI/CD pipeline custom roles for infrastructure deployment with explicit
      CREATE and UPDATE permissions and no broad vendor-managed roles.
  - csp: "aws"
    description: |
      **Customer-Managed IAM Policies:**
      Use customer-managed IAM policies with explicit action enumeration for
      control-plane actions. AWS-managed policies (e.g., AdministratorAccess,
      PowerUserAccess, service-specific FullAccess policies) must not be used
      for control-plane operations.

      **Service-Specific Policies:**
      Use customer-managed policies for S3, EC2, RDS, and Lambda with control-plane
      and data-plane action separation.

      **CI/CD Pipeline:**
      Use pipeline-specific IAM policies with explicit actions for infrastructure
      deployment. No AWS-managed admin policies attached to pipeline roles.
test_requirement:
  - id: "CR.SECURITY.035-TR-01"
    description: "Verify vendor-managed roles are not used for control-plane actions"
    gherkin: |
      Feature: No Vendor-Managed Roles for Control-Plane

        Scenario: Predefined roles are not used for control-plane actions
          Given a technology solution (service or solution)
          And an IAM principal or identity is created
          When checking the IAM configuration
          Then predefined or vendor-managed (CSP) roles are not used for control-plane actions
          And custom roles with explicit permission enumeration are used instead
  - id: "CR.SECURITY.035-TR-02"
    description: "Verify service accounts and pipelines use custom roles for control-plane"
    gherkin: |
      Feature: Custom Role Enforcement for Service Accounts and Pipelines

        Scenario: Service accounts use custom roles for control-plane
          Given a service account requires control-plane permissions
          When IAM role is assigned
          Then custom role is used with explicit control-plane permissions only
          And vendor-managed admin roles are not assigned

        Scenario: Vault SAs use custom roles for key management
          Given CloudKMS Vault service accounts require key rotation permissions
          When IAM roles are assigned
          Then custom roles with explicit key management permissions are used
          And vendor-managed iam.serviceAccountAdmin is not used

        Scenario: CI/CD pipeline SA uses custom role for deployment
          Given CI/CD pipeline requires infrastructure deployment permissions
          When IAM roles are assigned to pipeline service account
          Then custom role with explicit deployment permissions is used
          And vendor-managed admin roles are not used

---
id: "CR.SECURITY.037"
redline: "Segregation of duties must be defined per solution for all operational personas, and each persona must follow least-privilege principles"
status: "active"
environments:
  - "Sandbox"
  - "Service Engineering"
domain: "Identity and Access Management (IAM)"
data_classification: "All"
description: |
  Each solution must define distinct operational personas with non-conflicting duties
  and least-privilege permissions.

  No single identity may hold conflicting duties, including deployment and approval,
  key management and key usage, identity administration and identity usage,
  or security audit and operations administration.

  SoD enforcement must be implemented in IAM policy controls, validated via automated checks,
  and reviewed on material change and at least annually.

  Pipeline service accounts are exempt from human persona mapping only when they are
  single-purpose, control-plane-only, wildcard-free, monitored, and reviewed quarterly.
sa_principle:
  - "SA.9 - Least Privilege and Segregation of Duties"
policy_standard:
  - name: "Identity and Access Management (IAM) Standard (DOC-1244)"
    sections:
      - "3.1.3.1.a - Enforce SoD: no worker can perform multiple functions from Table A for the same activity"
      - "3.1.3.1.a - Systems must enforce systemic internal SoD (except Key Low/Low IS Risk)"
      - "Table A - Segregated Functions: Developing/Engineering, Approving, Implementing/Administering, Reviewing Privileged ID Activity, Administering IDs"
      - "3.3.1.1 - Refer to IAM Standard for SoD requirements"
      - "3.3.1.1 - Define incompatible duties per-policy-assessment"
      - "3.3.1.1 - Prohibition on performing incompatible duties (e.g., initiator cannot authorize own transaction)"
mitre_reference:
  - "TA0004: Privilege Escalation"
  - "T1098: Account Manipulation"
  - "T1078: Valid Accounts"
control_patterns:
  - csp: "aws"
    description: |
      Define a solution SoD matrix mapping persona-to-permissions and prohibited combinations.
      Enforce SoD in policy-as-code gates and continuous compliance checks.
      Keep pipeline service accounts single-purpose and control-plane-only.
      Document, justify, and review persona and pipeline permissions periodically.
  - csp: "gcp"
    description: |
      Use persona-specific customer-managed IAM policies and dedicated roles.
      Separate KMS administration roles from key usage roles.
      Keep pipeline roles single-purpose and control-plane-only.
      Use Access Analyzer to detect conflicting permissions on a principal.
  - csp: "gcp"
    description: |
      Use custom roles for persona mapping and avoid conflicting duty permissions.
      Keep pipeline service accounts dedicated to non-overlapping control-plane functions.
      Separate key rotation identities from key usage identities.
      Use IAM Recommender and Policy Analyzer to detect SoD violations.
test_requirement:
  - id: "CR.SECURITY.037-TR-01"
    description: "Verify solution defines distinct personas with segregated duties and least-privilege permissions"
    gherkin: |
      GIVEN a solution defines operational personas
      WHEN persona permissions are reviewed
      THEN each persona has documented least-privilege permissions
      AND conflicting duties are segregated
      AND a solution SoD matrix is documented
  - id: "CR.SECURITY.037-TR-02"
    description: "Verify no single identity accumulates conflicting permissions"
    gherkin: |
      GIVEN principals have IAM bindings
      WHEN effective permissions are analyzed
      THEN no principal has conflicting duty combinations
  - id: "CR.SECURITY.037-TR-03"
    description: "Verify pipeline service accounts are scoped to single function with control-plane-only permissions"
    gherkin: |
      GIVEN a pipeline service account is configured under the SoD exception
      WHEN its effective permissions are reviewed
      THEN it is single-purpose and control-plane-only
      AND no wildcard or data-plane permissions are present
      AND monitoring and quarterly review controls are in place
  - id: "CR.SECURITY.037-TR-04"
    description: "Verify pipeline and human personas have distinct, non-overlapping permission sets"
    gherkin: |
      GIVEN a solution uses both pipeline and human identities
      WHEN permission sets are compared
      THEN pipeline and human permission sets are distinct
      AND no conflicting control-plane write overlap exists

---
id: "CR.SECURITY.010"
redline: "Cloud resources must not be publicly accessible, with exceptions only for DMZ-isolated external services"
status: "active"
environments:
  - "Sandbox"
  - "Service Engineering"
domain: "Network"
data_classification: "All"
description: |
  Organization resources must not be made public. This applies to all resources including but not limited to:
  - Storage buckets (GCS, S3)
  - Database instances and endpoints
  - Compute instances and load balancers
  - API endpoints and webhooks
  - Network resources (VPCs, subnets)
  - Logging and monitoring endpoints

  Resources can be made public ONLY via authorized DMZ architectures with documented
  security controls including firewalls, WAF, DDoS protection, and ingress/egress restrictions.

  **Sandbox Validations:**
  Validate resource cannot be made public using one or more of the following: AWS Organizations
  SCP or RCP, IAM resource policies, VPC-SC's, Security Groups, Firewalls.

  **Valid Use-Case for Public:**
  If a valid use-case for public access exists, validate the resource is in the DMZ OU.
sa_principle:
  - "SA.8 - Minimize Attack Surface"
  - "SA.11 - Prevent Data Leakage"
  - "SA.12 - Protect Production Environment and Data"
policy_standard:
  - name: "Network Security Standard (NSS)"
    sections:
      - "3.5 NETWORK BOUNDARY PROTECTION"
      - "3.5.7.1 Demilitarized Zone (DMZ) Definition and Controls"
mitre_reference:
  - "T1562: Impair Defenses"
control_patterns:
  - csp: "gcp"
    description: |
      **Disable Default VPCs:**
      Default VPCs come with permissive firewall rules and must be disabled. All new projects
      must not contain a network named "default" or any auto-created firewall rules.

      **Ingress Restriction:**
      Ingress from the public internet must not be allowed. Deny ingress from 0.0.0.0/0 on
      all VPCs not designated as DMZ. Firewall rules must explicitly deny public ingress.

      **Egress Restriction:**
      Egress to the public Internet must not be allowed. Deny egress to 0.0.0.0/0 on all
      VPCs not designated as DMZ. Subnets must not have default routes to internet gateways.

      **Cloud Storage Bucket Public Access:**
      Prevent public access to Cloud Storage buckets. Buckets must not have "allUsers" or
      "allAuthenticatedUsers" in IAM policies, and public access prevention should be
      enabled where available.

      **Cloud SQL Instances Public IP:**
      Prevent public IP assignment to Cloud SQL instances. Ensure instances are deployed
      within private VPC networks and use Private Service Access.

      **Load Balancer Scheme:**
      Ensure internal load balancers are used for internal services, and external load balancers
      are only used for DMZ-isolated public services with appropriate WAF/DDoS.

      **Logging and Monitoring Public Endpoints:**
      Ensure Cloud Logging and Cloud Monitoring endpoints are not publicly exposed.

      **DMZ Enforcement for Public Resources:**
      If any resource is identified as public, verify it resides within a designated DMZ project/folder
      and adheres to DMZ controls (e.g., WAF, firewall, ingress/egress restrictions).
  - csp: "aws"
    description: |
      **Disable Default VPCs:**
      Default VPCs must be deleted or restricted in all AWS regions. Security groups and
      NACLs must not allow 0.0.0.0/0 ingress or egress.

      **Ingress Restriction:**
      Security groups must deny all public ingress. Resources must not have public IPs
      unless in a DMZ architecture with WAF, DDoS protection, and documented controls.

      **Egress Restriction:**
      Egress to the public internet must be routed through approved NAT gateways in the DMZ OU or
      proxies with logging and filtering.

      **S3 Bucket Public Access:**
      Prevent public access to S3 buckets. Buckets must have Block Public Access enabled at
      the account or bucket level, and bucket policies must not allow public access.

      **RDS Instances Public IP:**
      Prevent public IP assignment to RDS instances. Ensure instances are deployed in private
      subnets and have Publicly Accessible set to "No".

      **EC2 Public IP:**
      Prevent direct public IP assignment to EC2 instances in non-DMZ environments. All inbound/outbound
      traffic should be controlled by security groups and network ACLs.

      **Load Balancer Scheme:**
      Ensure Internal-facing Application Load Balancers (ALBs) or Network Load Balancers (NLBs)
      are used for internal services. Internet-facing load balancers are only for DMZ-isolated
      public services with appropriate WAF/DDoS.

      **API Gateway Public Exposure:**
      Ensure API Gateway endpoints are private where possible, or secured with WAF/throttling
      when internet-facing.

      **CloudWatch Logs/Metrics Public Exposure:**
      Ensure CloudWatch Logs and Metrics endpoints are not publicly exposed.

      **DMZ Enforcement for Public Resources:**
      If any resource is identified as public, verify it resides within a designated DMZ account/OU
      and adheres to DMZ controls (e.g., WAF, firewall, ingress/egress restrictions).
test_requirement:
  - id: "CR.SECURITY.010-TR-01"
    description: "Verify GCP project does not contain default VPC or auto-created firewall rules"
    gherkin: |
      Feature: No Default VPC or Public Exposure - GCP Project

        Scenario: Project does not contain default network
          Given a GCP Project is created
          And the Project is not used in the DMZ
          When the Project is provisioned
          Then the Project MUST NOT contain a network named "default"
          And the Project MUST NOT contain any auto-created firewall rules
  - id: "CR.SECURITY.010-TR-02"
    description: "Verify VPC does not allow public ingress"
    gherkin: |
      Feature: No Public Ingress on VPC

        Scenario: VPC does not allow public ingress
          Given a GCP VPC is created
          And the VPC is not used in the DMZ
          Then the VPC MUST contain a Firewall rule
          And the Firewall rule MUST NOT allow ingress on 0.0.0.0/0
  - id: "CR.SECURITY.010-TR-03"
    description: "Verify subnet does not have default route to internet"
    gherkin: |
      Feature: No Default Route to Internet

        Scenario: Subnet does not have default route to internet
          Given a GCP VPC is created
          And the VPC is not used in the DMZ
          And a Subnet is created
          Then the Subnet MUST NOT contain a default route (0.0.0.0/0) with next hop Internet Gateway
  - id: "CR.SECURITY.010-TR-04"
    description: "Verify Cloud Storage buckets are not publicly accessible."
    gherkin: |
      Feature: No Public Access on Cloud Storage Buckets

        Scenario: Cloud Storage bucket is not publicly accessible
          Given a Cloud Storage bucket exists
          And the bucket is not used in the DMZ
          When the bucket MUST NOT have IAM permissions for "allUsers" or "allAuthenticatedUsers"
          And the bucket SHOULD have Public Access Prevention enabled
  - id: "CR.SECURITY.010-TR-05"
    description: "Verify Cloud SQL instances do not have public IPs."
    gherkin: |
      Feature: No Public IP for Cloud SQL Instances

        Scenario: Cloud SQL instance does not have a public IP
          Given a Cloud SQL instance exists
          And the instance is not used in the DMZ
          When the instance is provisioned
          Then the instance MUST NOT have a public IP address enabled
  - id: "CR.SECURITY.010-TR-06"
    description: "Verify External Load Balancers are in DMZ if public."
    gherkin: |
      Feature: External Load Balancers in DMZ

        Scenario: Public Load Balancer is in a DMZ
          Given a Google Cloud Load Balancer exists
          When the Load Balancer has a public IP address
          Then the Load Balancer MUST be deployed within a DMZ-designated project/folder
          And the Load Balancer MUST have WAF and DDoS protection enabled
  - id: "CR.SECURITY.010-TR-07"
    description: "Verify S3 buckets are not publicly accessible."
    gherkin: |
      Feature: No Public Access on S3 Buckets

        Scenario: S3 bucket is not publicly accessible
          Given an S3 bucket exists
          And the bucket is not used in the DMZ
          Then the bucket MUST have Block Public Access enabled
          And the bucket must not have policies allowing "Allow" * for principal "*" or "AuthenticatedUsers"
  - id: "CR.SECURITY.010-TR-08"
    description: "Verify RDS instances do not have public IPs."
    gherkin: |
      Feature: No Public IP for RDS Instances

        Scenario: RDS instance does not have a public IP
          Given an RDS instance exists
          And the instance is not used in the DMZ
          When the instance is provisioned
          Then the instance MUST have "Publicly Accessible" set to "No"
  - id: "CR.SECURITY.010-TR-09"
    description: "Verify EC2 instances do not have public IPs in non-DMZ."
    gherkin: |
      Feature: No Public IP for EC2 Instances in Non-DMZ

        Scenario: EC2 instance does not have a public IP in non-DMZ
          Given an EC2 instance exists
          And the instance is not used in the DMZ
          Then the instance MUST NOT have a public IP address assigned
  - id: "CR.SECURITY.010-TR-10"
    description: "Verify Internet-facing Load Balancers are in DMZ if public."
    gherkin: |
      Feature: Internet-facing Load Balancers in DMZ

        Scenario: Public Load Balancer is in a DMZ
          Given an AWS Load Balancer exists
          When the Load Balancer is Internet-facing
          Then the Load Balancer MUST be deployed within a DMZ-designated account/OU
          And the Load Balancer MUST have WAF and DDoS protection enabled
  - id: "CR.SECURITY.010-TR-11"
    description: "Verify API Gateway endpoints are not publicly exposed unless in DMZ."
    gherkin: |
      Feature: API Gateway Endpoints Secured

        Scenario: API Gateway endpoint is not publicly exposed or is in DMZ
          Given an AWS API Gateway endpoint exists
          When the API Gateway endpoint is not private
          Then the API Gateway endpoint MUST be within a DMZ-designated account/OU
          And the API Gateway endpoint SHOULD have WAF and throttling enabled
  - id: "CR.SECURITY.010-TR-12"
    description: "Verify CloudWatch Logs/Metrics access endpoints are not publicly accessible."
    gherkin: |
      Feature: CloudWatch Logs/Metrics Not Public

        Scenario: CloudWatch Logs/Metrics access endpoints are not publicly accessible
          Given CloudWatch Logs or Metrics exist
          Then their access endpoints MUST NOT be publicly accessible
  - id: "CR.SECURITY.010-TR-13"
    description: "Validate DMZ designation for public resources (AWS)."
    gherkin: |
      Feature: DMZ Designation for Public Resources

        Scenario: Public resource is in a designated DMZ
          Given a resource requires public access
          Then the resource MUST be deployed within a designated DMZ AWS account or OU
          And the DMZ must have documented security controls including WAF, DDoS protection, and ingress/egress restrictions
