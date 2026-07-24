package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
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

func (c *bddContext) registerGAPISteps(sc *godog.ScenarioContext) {
	sc.Step(`^I list the enabled services in the project$`, c.iListTheEnabledServicesInTheProject)
	sc.Step(`^I retrieve the Google Cloud APIs Discovery document$`, c.iRetrieveTheGoogleCloudAPIsDiscoveryDocument)
	sc.Step(`^all enabled APIs should have at least one General Availability version$`, c.allEnabledAPIsShouldHaveAtLeastOneGeneralAvailabilityVersion)
}

func (c *bddContext) iListTheEnabledServicesInTheProject() error {
	ctx := context.Background()
	service, err := serviceusage.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to create serviceusage client: %w", err)
	}

	parent := "projects/" + c.projectID
	pageToken := ""
	for {
		req := service.Services.List(parent).Filter("state:ENABLED").Context(ctx)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		resp, err := req.Do()
		if err != nil {
			return fmt.Errorf("failed to list enabled services: %w", err)
		}
		for _, s := range resp.Services {
			parts := strings.Split(s.Name, "/")
			serviceName := parts[len(parts)-1]
			c.enabledServices = append(c.enabledServices, serviceName)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return nil
}

func (c *bddContext) iRetrieveTheGoogleCloudAPIsDiscoveryDocument() error {
	client := &http.Client{Timeout: 15 * time.Second}
	discResp, err := client.Get("https://discovery.googleapis.com/discovery/v1/apis")
	if err != nil {
		return fmt.Errorf("failed to fetch Google APIs Discovery document: %w", err)
	}
	defer discResp.Body.Close()

	var discoveryData DiscoveryResponse
	if err := json.NewDecoder(discResp.Body).Decode(&discoveryData); err != nil {
		return fmt.Errorf("failed to decode Google APIs Discovery document: %w", err)
	}

	c.serviceNameToVersions = make(map[string][]string)
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
			c.serviceNameToVersions[host] = append(c.serviceNameToVersions[host], item.Version)
		}
	}
	return nil
}

func (c *bddContext) allEnabledAPIsShouldHaveAtLeastOneGeneralAvailabilityVersion() error {
	var nonGAServices []string
	for _, serviceName := range c.enabledServices {
		versions, exists := c.serviceNameToVersions[serviceName]
		if !exists {
			// Some internal or system APIs might not be present in the public discovery directory.
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
		}
	}

	if len(nonGAServices) > 0 {
		return fmt.Errorf("failed: %d enabled GCP APIs are not in General Availability (GA) status: %v", len(nonGAServices), nonGAServices)
	}
	return nil
}
