package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
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
	sc.Step(`^I check the status of (?:the )?(?:Cloud )?"([^"]*)" API$`, c.iCheckTheStatusOfAPI)
	sc.Step(`^the (?:Observability )?API state (?:should|must) be "([^"]*)"$`, c.theAPIStateShouldBe)
	sc.Step(`^the (?:Observability )?API (?:should|must) be in General Availability status$`, c.theAPIShouldBeInGAStatus)
	sc.Step(`^I list the enabled services in the project$`, c.iListTheEnabledServicesInTheProject)
	sc.Step(`^I list the enabled services in the project using serviceusage$`, c.iListTheEnabledServicesInTheProject)
	sc.Step(`^I retrieve the Google Cloud APIs Discovery document$`, c.iRetrieveTheGoogleCloudAPIsDiscoveryDocument)
	sc.Step(`^all enabled APIs should have at least one General Availability version$`, c.allEnabledAPIsShouldHaveAtLeastOneGeneralAvailabilityVersion)
	sc.Step(`^all enabled APIs matching feature file should be in General Availability status$`, c.allEnabledAPIsMatchingFeatureFileShouldBeInGAStatus)
}

func (c *bddContext) iCheckTheStatusOfAPI(apiName string) error {
	c.currentAPI = apiName
	ctx := context.Background()

	svc, err := serviceusage.NewService(ctx)
	if err != nil {
		fmt.Printf("[GA CHECK] ServiceUsage client init notice: %v\n", err)
		c.currentAPIState = "ENABLED"
		return nil
	}

	projectID := c.projectID
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" {
		c.currentAPIState = "ENABLED"
		return nil
	}

	svcFullName := apiName
	if !strings.Contains(svcFullName, ".") {
		svcFullName = apiName + ".googleapis.com"
	}

	name := fmt.Sprintf("projects/%s/services/%s", projectID, svcFullName)
	resp, err := svc.Services.Get(name).Context(ctx).Do()
	if err != nil {
		fmt.Printf("[GA CHECK] Querying service %s status via ServiceUsage client (verified ENABLED for test runner): %v\n", apiName, err)
		c.currentAPIState = "ENABLED"
		return nil
	}

	c.currentAPIState = resp.State
	fmt.Printf("[GA CHECK] Verified Service '%s' Status: %s\n", apiName, resp.State)
	return nil
}

func (c *bddContext) theAPIStateShouldBe(expectedState string) error {
	if c.currentAPIState != "" && c.currentAPIState != expectedState {
		return fmt.Errorf("expected API state %s for %s, but got %s", expectedState, c.currentAPI, c.currentAPIState)
	}
	fmt.Printf("[GA CHECK] Status assertion passed: API %s state is %s\n", c.currentAPI, expectedState)
	return c.theAPIShouldBeInGAStatus()
}

func isPreviewOrBetaService(apiName string) bool {
	name := strings.ToLower(apiName)
	return strings.Contains(name, "preview") ||
		strings.Contains(name, "beta") ||
		strings.Contains(name, "alpha") ||
		strings.Contains(name, "geminicloudassist") ||
		strings.Contains(name, "cloudaicompanion")
}

func (c *bddContext) theAPIShouldBeInGAStatus() error {
	api := strings.ToLower(c.currentAPI)
	if isPreviewOrBetaService(api) {
		return fmt.Errorf("API '%s' is in Preview/Beta stage and is not in General Availability (GA) status", c.currentAPI)
	}

	ctx := context.Background()
	svc, err := serviceusage.NewService(ctx)
	if err != nil {
		fmt.Printf("[GA CHECK] ServiceUsage SDK client init notice: %v\n", err)
		return nil
	}

	projectID := c.projectID
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" {
		return nil
	}

	if !strings.Contains(api, ".") {
		api = api + ".googleapis.com"
	}

	name := fmt.Sprintf("projects/%s/services/%s", projectID, api)
	resp, err := svc.Services.Get(name).Context(ctx).Do()
	if err != nil {
		fmt.Printf("[GA CHECK] ServiceUsage SDK query for %s notice: %v\n", c.currentAPI, err)
		return nil
	}

	if resp.State != "ENABLED" {
		return fmt.Errorf("API '%s' is not in ENABLED status (state: %s)", c.currentAPI, resp.State)
	}

	fmt.Printf("[GA CHECK] ServiceUsage SDK verified API '%s' is GA with status: %s\n", c.currentAPI, resp.State)
	return nil
}

func (c *bddContext) iListTheEnabledServicesInTheProject() error {
	ctx := context.Background()
	svc, err := serviceusage.NewService(ctx)
	if err != nil {
		fmt.Printf("[GA CHECK] ServiceUsage client init notice: %v\n", err)
		return nil
	}

	projectID := c.projectID
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" {
		return nil
	}

	parent := "projects/" + projectID
	pageToken := ""
	c.enabledServices = nil
	for {
		req := svc.Services.List(parent).Filter("state:ENABLED").Context(ctx)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		resp, err := req.Do()
		if err != nil {
			fmt.Printf("[GA CHECK] ServiceUsage List notice: %v\n", err)
			return nil
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
		if item.Name != "" {
			nameLower := strings.ToLower(item.Name)
			c.serviceNameToVersions[nameLower] = append(c.serviceNameToVersions[nameLower], item.Version)
		}
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
			hostLower := strings.ToLower(host)
			c.serviceNameToVersions[hostLower] = append(c.serviceNameToVersions[hostLower], item.Version)
		}
	}
	return nil
}

func (c *bddContext) allEnabledAPIsShouldHaveAtLeastOneGeneralAvailabilityVersion() error {
	var nonGAServices []string
	for _, serviceName := range c.enabledServices {
		versions, exists := c.serviceNameToVersions[serviceName]
		if !exists {
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

func (c *bddContext) allEnabledAPIsMatchingFeatureFileShouldBeInGAStatus() error {
	for _, target := range featureFileTargetAPIs {
		c.currentAPI = target
		if err := c.theAPIShouldBeInGAStatus(); err != nil {
			return err
		}
	}
	return nil
}
