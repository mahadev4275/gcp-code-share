package tests

import (
	"context"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	serviceusage "google.golang.org/api/serviceusage/v1"
)

func (c *bddContext) registerObservabilitySteps(sc *godog.ScenarioContext) {
	sc.Step(`^I check the status of the Cloud "([^"]*)" API$`, c.iCheckTheStatusOfTheCloudObsAPI)
	sc.Step(`^the Observability API state should be "([^"]*)"$`, c.theCloudObsAPIStateShouldBe)
}

func (c *bddContext) iCheckTheStatusOfTheCloudObsAPI(api string) error {
	ctx := context.Background()
	service, err := serviceusage.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to create serviceusage client: %w", err)
	}

	name := "projects/" + c.projectID + "/services/" + strings.ToLower(api) + ".googleapis.com"
	resp, err := service.Services.Get(name).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch service status for %s: %w", name, err)
	}

	c.traceServiceState = resp.State
	return nil
}

func (c *bddContext) theCloudObsAPIStateShouldBe(expectedState string) error {
	if c.traceServiceState != expectedState {
		return fmt.Errorf("expected API to be %s, but got %s", expectedState, c.traceServiceState)
	}
	return nil
}
