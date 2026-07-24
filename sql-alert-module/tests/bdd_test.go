package tests

import (
	"context"
	"flag"
	"testing"

	"github.com/cucumber/godog"
)

var godogTags = flag.String("godog.tags", "", "filter scenarios by tags")

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			c := &bddContext{}
			c.registerSteps(sc)

			sc.Before(func(ctx context.Context, scenario *godog.Scenario) (context.Context, error) {
				_, changes, err := generateModulePlanJSON(t)
				if err != nil {
					return ctx, err
				}
				c.plannedChanges = changes

				if err := runConftestAgainstModule(t); err != nil {
					return ctx, err
				}

				return ctx, nil
			})
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t,
			Tags:     *godogTags,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
