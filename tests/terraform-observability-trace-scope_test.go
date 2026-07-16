package tests

import (
	"context"
	"fmt"

	"github.com/cucumber/godog"
	serviceusage "google.golang.org/api/serviceusage/v1"
)

func (c *bddContext) registerObservabilitySteps(sc *godog.ScenarioContext) {
	sc.Step(`^I check the status of the Cloud Trace API$`, c.iCheckTheStatusOfTheCloudTraceAPI)
	sc.Step(`^the Cloud Trace API state should be "([^"]*)"$`, c.theCloudTraceAPIStateShouldBe)
}

func (c *bddContext) iCheckTheStatusOfTheCloudTraceAPI() error {
	ctx := context.Background()
	service, err := serviceusage.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to create serviceusage client: %w", err)
	}

	name := "projects/" + c.projectID + "/services/cloudtrace.googleapis.com"
	resp, err := service.Services.Get(name).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch service status for %s: %w", name, err)
	}

	c.traceServiceState = resp.State
	return nil
}

func (c *bddContext) theCloudTraceAPIStateShouldBe(expectedState string) error {
	if c.traceServiceState != expectedState {
		return fmt.Errorf("expected Cloud Trace API to be %s, but got %s", expectedState, c.traceServiceState)
	}
	return nil
}
