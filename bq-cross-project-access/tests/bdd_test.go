package tests

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/cucumber/godog"
)

var (
	godogTags   = flag.String("godog.tags", "", "filter scenarios by tags")
	tfQuietFlag = flag.Bool("tf.quiet", true, "suppress verbose Terraform CLI output (default true; set -tf.quiet=false to view Terraform logs)")
)

func isTFQuiet() bool {
	if v := os.Getenv("TF_QUIET"); v != "" {
		return v != "false" && v != "0"
	}
	if tfQuietFlag != nil {
		return *tfQuietFlag
	}
	return true
}

func TestBigQueryCrossProjectFeatures(t *testing.T) {
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
