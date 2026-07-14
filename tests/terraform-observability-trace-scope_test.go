package tests

import (
	"context"
	"flag"
	"testing"

	serviceusage "google.golang.org/api/serviceusage/v1"
)

var projectID string

func init() {
	flag.StringVar(&projectID, "project_id", "", "Google Cloud Project ID")
}

func TestServiceUsage(t *testing.T) {
	if projectID == "" {
		t.Fatal("project_id flag is required. Usage: go test ./tests/... -args -project_id=YOUR_PROJECT_ID")
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
