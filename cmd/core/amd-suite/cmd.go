package main

import (
	"fmt"
	"sort"

	"github.com/9elements/converged-security-suite/v2/pkg/test"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	log "github.com/sirupsen/logrus"

	a "github.com/logrusorgru/aurora"
)

type context struct {
	logpath string
}

var cli struct {
	ExecTests execTestsCmd `cmd:"" help:"Executes tests given by test set" short:"e"`

	Version versionCmd `cmd:"" help:"Prints the version of the program"`
	Debug   bool       `help:"Enable debug mode."`
}

type versionCmd struct{}

type execTestsCmd struct {
	Set string `required:"" short:"s" default:"all" help:"Select a subset, or all test that should be run"`
}

func (v *versionCmd) Run(ctx *context) error {
	tools.ShowVersion(programName, gittag, gitcommit)
	return nil
}

func (e *execTestsCmd) Run(ctx *context) error {
	preset := &test.PreSet{}
	switch e.Set {
	case "general":
		run("AMD General", getTests("general"), preset)
	case "psb":
		run("AMD PSB", getTests("psb"), preset)
	case "sme":
		run("AMD SME", getTests("sme"), preset)
	case "sev":
		run("AMD SEV", getTests("sev"), preset)
	case "sevsnp":
		run("AMD SEV-SNP", getTests("sevsnp"), preset)
	case "all":
		fmt.Println("Running all tests")
		run("AMD", getTests("all"), preset)
	default:
		return fmt.Errorf("Unknown test set: %s", e.Set)
	}

	return nil
}

func getTests(group string) []*test.Test {
	switch group {
	case "psb":
		return test.TestsAMDPSP
	case "sme":
		return test.TestsAMDSME
	case "sev":
		return test.TestsAMDSEV
	case "sevsnp":
		return test.TestsAMDSEVSNP
	case "all":
		return test.TestsAMD
	default:
		// For "general" or unknown groups, return just the family/model test
		return []*test.Test{}
	}
}

func run(testGroup string, tests []*test.Test, preset *test.PreSet) bool {
	result := false

	hwAPI := hwapi.GetAPI()

	log.Infof("%s tests (%d tests)", a.Bold(a.Gray(20-1, testGroup).BgGray(4-1)), len(tests))
	log.Info("--------------------------------------------------")
	for idx := range tests {
		if len(testnos) > 0 {
			// SearchInt returns an index where to "insert" idx
			i := sort.SearchInts(testnos, idx)
			if i >= len(testnos) {
				continue
			}
			// still here? i must be within testnos.
			if testnos[i] != idx {
				continue
			}
		}

		_ = tests[idx].Run(hwAPI, preset)
	}

	for index := range tests {
		var s string

		if tests[index].Status == test.NotImplemented {
			continue
		}
		if tests[index].Result == test.ResultNotRun {
			continue
		}
		s += fmt.Sprintf("%02d - ", index)
		s += fmt.Sprintf("%-40s: ", a.Bold(tests[index].Name))

		if tests[index].Result == test.ResultPass {
			s += fmt.Sprintf("%-20s", a.Bold(a.Green(tests[index].Result)))
		} else {
			s += fmt.Sprintf("%-20s", a.Bold(a.Red(tests[index].Result)))
			result = false
		}
		if tests[index].ErrorText != "" {
			s += fmt.Sprintf(" (%s)", tests[index].ErrorText)
		} else if len(tests[index].ErrorText) == 0 && tests[index].Result == test.ResultFail {
			s += " (No error text given)"
		}
		log.Infof("%s", s)

	}

	return result
}
