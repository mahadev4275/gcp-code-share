package tests

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	serviceusage "google.golang.org/api/serviceusage/v1"
)

type DiscoveryItem struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	DiscoveryRestUrl string `json:"discoveryRestUrl"`
}

type DiscoveryResponse struct {
	Items []DiscoveryItem `json:"items"`
}

func isGAVersion(version string) bool {
	v := strings.ToLower(version)
	return !strings.Contains(v, "beta") && !strings.Contains(v, "alpha") && !strings.Contains(v, "preview")
}

func TestGCPAPIsGeneralAvailability(t *testing.T) {
	if projectID == "" {
		t.Fatal("project_id flag is required. Usage: go test ./tests/... -args -project_id=YOUR_PROJECT_ID")
	}

	ctx := context.Background()
	service, err := serviceusage.NewService(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Fetch the list of enabled services for the project
	var enabledServices []string
	parent := "projects/" + projectID
	pageToken := ""
	for {
		req := service.Services.List(parent).Filter("state:ENABLED").Context(ctx)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		resp, err := req.Do()
		if err != nil {
			t.Fatalf("Failed to list enabled services: %v", err)
		}
		for _, s := range resp.Services {
			parts := strings.Split(s.Name, "/")
			serviceName := parts[len(parts)-1]
			enabledServices = append(enabledServices, serviceName)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	// 2. Fetch the discovery document to build the service-to-version map
	client := &http.Client{Timeout: 15 * time.Second}
	discResp, err := client.Get("https://discovery.googleapis.com/discovery/v1/apis")
	if err != nil {
		t.Fatalf("Failed to fetch Google APIs Discovery document: %v", err)
	}
	defer discResp.Body.Close()

	var discoveryData DiscoveryResponse
	if err := json.NewDecoder(discResp.Body).Decode(&discoveryData); err != nil {
		t.Fatalf("Failed to decode Google APIs Discovery document: %v", err)
	}

	serviceNameToVersions := make(map[string][]string)
	for _, item := range discoveryData.Items {
		if item.DiscoveryRestUrl == "" {
			continue
		}
		u, err := url.Parse(item.DiscoveryRestUrl)
		if err != nil {
			continue
		}
		host := u.Host
		if strings.Contains(host, ":") {
			h, _, err := net.SplitHostPort(host)
			if err == nil {
				host = h
			}
		}
		if host != "" {
			serviceNameToVersions[host] = append(serviceNameToVersions[host], item.Version)
		}
	}

	// 3. Verify GA status for all enabled APIs
	var nonGAServices []string
	for _, serviceName := range enabledServices {
		versions, exists := serviceNameToVersions[serviceName]
		if !exists {
			// Some internal or system APIs might not be present in the public discovery directory.
			t.Logf("Warning: Service %s not found in Google APIs Discovery directory. Skipping GA status check.", serviceName)
			continue
		}

		isGA := false
		for _, v := range versions {
			if isGAVersion(v) {
				isGA = true
				break
			}
		}

		if !isGA {
			nonGAServices = append(nonGAServices, serviceName)
			t.Errorf("Service %s is enabled but has no General Availability (GA) versions. Available versions: %v", serviceName, versions)
		}
	}

	if len(nonGAServices) > 0 {
		t.Errorf("Failed: %d enabled GCP APIs are not in General Availability (GA) status: %v", len(nonGAServices), nonGAServices)
	} else {
		t.Logf("Success: All checkable enabled GCP APIs are in General Availability (GA) status.")
	}
}
