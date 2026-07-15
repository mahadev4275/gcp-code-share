package tests

import (
	"context"
	"os"
	"testing"

	serviceusage "google.golang.org/api/serviceusage/v1"
)

func TestServiceUsage(t *testing.T) {
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" {
		t.Fatal("GCP Project ID must be set via the GOOGLE_CLOUD_PROJECT or PROJECT_ID environment variable")
	}

	ctx := context.Background()
	service, err := serviceusage.NewService(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Checking cloudtrace as the representative 'observability' API for this scope
	name := "projects/" + projectID + "/services/cloudtrace.googleapis.com"
	resp, err := service.Services.Get(name).Context(ctx).Do()
	if err != nil {
		t.Fatalf("Failed to fetch service status for %s: %v", name, err)
	}

	if resp.State != "ENABLED" {
		t.Errorf("Expected service %s to be ENABLED, but got %s", name, resp.State)
	}
}
