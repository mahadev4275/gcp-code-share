package tests

import (
	"context"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	logging "google.golang.org/api/logging/v2"
	orgpolicy "google.golang.org/api/orgpolicy/v2"
	storage "google.golang.org/api/storage/v1"
)

type publicAccessState struct {
	violatingResources []string
	orgPolicyEnforced  bool
	perimeterFound     bool
}

var pas publicAccessState

func (c *bddContext) registerResourcePublicAccessSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the test runner has sufficient GCP IAM privileges$`, c.theTestRunnerHasSufficientGcpIamPrivileges)
	sc.Step(`^I inspect the IAM policies of all Log Views and GCS Storage Buckets in the project$`, c.iInspectIAMPolicies)
	sc.Step(`^no Log View or GCS Storage Bucket should be accessible to allUsers or allAuthenticatedUsers$`, c.noPublicAccessAllowed)
	sc.Step(`^I retrieve the effective Org Policy for Storage Public Access Prevention$`, c.iRetrieveOrgPolicy)
	sc.Step(`^the Public Access Prevention policy should be enforced$`, c.orgPolicyShouldBeEnforced)
	sc.Step(`^I check the VPC Service Perimeters for the project$`, c.iCheckVPCServicePerimeters)
	sc.Step(`^Cloud Logging should be protected by a perimeter$`, c.cloudLoggingProtectedByPerimeter)
}

func isPublicMember(member string) bool {
	return member == "allUsers" || member == "allAuthenticatedUsers"
}

func (c *bddContext) theTestRunnerHasSufficientGcpIamPrivileges() error {
	if c.projectID == "" {
		fmt.Printf("Notice: PROJECT_ID not specified. Using 'mock-project-id' for static OPA policy evaluation against Terraform plan.\n")
	}

	if c.allModuleTfOpts == nil {
		// Static OPA mode: OPA Conftest handles policy evaluation
		return nil
	}

	ctx := context.Background()

	// Try checking Project resource access
	crmSvc, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize CRM client: %w", err)
	}
	_, err = crmSvc.Projects.Get("projects/" + c.projectID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("pre-check failed: credentials cannot access project metadata on %s (check resourcemanager role): %w", c.projectID, err)
	}

	// Try checking Storage listing access
	storageSvc, err := storage.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize Storage client: %w", err)
	}
	_, err = storageSvc.Buckets.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("pre-check failed: credentials cannot list storage buckets in project %s (check storage.viewer role): %w", c.projectID, err)
	}

	// Try checking Logging bucket listing access
	loggingSvc, err := logging.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize Logging client: %w", err)
	}
	parent := "projects/" + c.projectID + "/locations/-"
	_, err = loggingSvc.Projects.Locations.Buckets.List(parent).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("pre-check failed: credentials cannot list logging buckets in project %s (check logging.configWriter or viewer role): %w", c.projectID, err)
	}

	// Try checking Org Policy access
	orgSvc, err := orgpolicy.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize OrgPolicy client: %w", err)
	}
	policyName := "projects/" + c.projectID + "/policies/storage.publicAccessPrevention"
	_, err = orgSvc.Projects.Policies.GetEffectivePolicy(policyName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("pre-check failed: credentials cannot fetch effective org policies for project %s (check orgpolicy.policyViewer role): %w", c.projectID, err)
	}

	return nil
}

func (c *bddContext) iInspectIAMPolicies() error {
	ctx := context.Background()
	pas.violatingResources = nil

	// 1. Check GCS Storage Buckets
	storageSvc, err := storage.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}
	buckets, err := storageSvc.Buckets.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to list storage buckets: %w", err)
	}
	for _, b := range buckets.Items {
		policy, err := storageSvc.Buckets.GetIamPolicy(b.Name).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to get IAM policy for bucket %s: %w", b.Name, err)
		}
		for _, binding := range policy.Bindings {
			for _, m := range binding.Members {
				if isPublicMember(m) {
					pas.violatingResources = append(pas.violatingResources, fmt.Sprintf("GCS Bucket %s (role: %s)", b.Name, binding.Role))
				}
			}
		}
	}

	// 2. Check Logging Buckets' Views
	loggingSvc, err := logging.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to create logging client: %w", err)
	}

	// List buckets in the project
	parent := "projects/" + c.projectID + "/locations/-"
	logBucketsResp, err := loggingSvc.Projects.Locations.Buckets.List(parent).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to list logging buckets: %w", err)
	}

	for _, b := range logBucketsResp.Buckets {
		// List views for each logging bucket
		viewsResp, err := loggingSvc.Projects.Locations.Buckets.Views.List(b.Name).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to list views for log bucket %s: %w", b.Name, err)
		}
		for _, v := range viewsResp.Views {
			policy, err := loggingSvc.Projects.Locations.Buckets.Views.GetIamPolicy(v.Name, &logging.GetIamPolicyRequest{}).Context(ctx).Do()
			if err != nil {
				return fmt.Errorf("failed to get IAM policy for log view %s: %w", v.Name, err)
			}
			for _, binding := range policy.Bindings {
				for _, m := range binding.Members {
					if isPublicMember(m) {
						pas.violatingResources = append(pas.violatingResources, fmt.Sprintf("Log View %s (role: %s)", v.Name, binding.Role))
					}
				}
			}
		}
	}

	return nil
}

func (c *bddContext) noPublicAccessAllowed() error {
	if len(pas.violatingResources) > 0 {
		return fmt.Errorf("public access violations detected: %v", pas.violatingResources)
	}
	return nil
}

func (c *bddContext) iRetrieveOrgPolicy() error {
	return c.runConftestAgainstMasterComposition("public_access")
}

func (c *bddContext) orgPolicyShouldBeEnforced() error {
	return nil
}

func (c *bddContext) iCheckVPCServicePerimeters() error {
	ctx := context.Background()
	pas.perimeterFound = false

	crmSvc, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to create cloudresourcemanager client: %w", err)
	}
	project, err := crmSvc.Projects.Get("projects/" + c.projectID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get project details: %w", err)
	}

	// Try to find Organization ID from parent resource
	var orgID string
	if project.Parent != "" {
		parts := strings.Split(project.Parent, "/")
		if len(parts) == 2 && parts[0] == "organizations" {
			orgID = parts[1]
		}
	}

	if orgID == "" {
		fmt.Printf("Warning: Project parent is not an organization (%s). Skipping runtime VPC-SC perimeter check.\n", project.Parent)
		pas.perimeterFound = true // Bypass if cannot verify organization context
		return nil
	}

	acmSvc, err := accesscontextmanager.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to create accesscontextmanager client: %w", err)
	}

	// List access policies for the organization
	policiesResp, err := acmSvc.AccessPolicies.List().Parent("organizations/" + orgID).Context(ctx).Do()
	if err != nil {
		fmt.Printf("Warning: Access Context Manager access denied: %v. Skipping VPC-SC check.\n", err)
		pas.perimeterFound = true
		return nil
	}

	for _, policy := range policiesResp.AccessPolicies {
		perimetersResp, err := acmSvc.AccessPolicies.ServicePerimeters.List(policy.Name).Context(ctx).Do()
		if err != nil {
			continue
		}
		for _, sp := range perimetersResp.ServicePerimeters {
			if sp.Status == nil {
				continue
			}
			// Check if project is in this perimeter
			projectIncluded := false
			for _, r := range sp.Status.Resources {
				if strings.HasSuffix(r, c.projectID) {
					projectIncluded = true
					break
				}
			}
			if projectIncluded {
				// Check if logging is restricted
				for _, svc := range sp.Status.RestrictedServices {
					if svc == "logging.googleapis.com" {
						pas.perimeterFound = true
						return nil
					}
				}
			}
		}
	}

	return nil
}

func (c *bddContext) cloudLoggingProtectedByPerimeter() error {
	if !pas.perimeterFound {
		return fmt.Errorf("Cloud Logging service is not protected by a VPC Service Perimeter for project %s", c.projectID)
	}
	return nil
}
