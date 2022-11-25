package bootengine

import (
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Step struct {
	Step         types.Step
	Actions      types.Actions
	MeasuredData []types.MeasuredData
	Issues       StepIssues
}

type Log []Step

func (log Log) GoString() string {
	var result strings.Builder
	for idx, step := range log {
		fmt.Fprintf(&result, "%d. %#v:\n", idx, step.Step)
		if len(step.MeasuredData) > 0 {
			fmt.Fprintf(&result, "\tMeasuredData:\n")
			for idx, measuredData := range step.MeasuredData {
				fmt.Fprintf(&result, "\t\t%d. %s\n", idx, nestedGoStringOf(measuredData))
			}
		}
		if _, ok := step.Step.(types.StaticStep); !ok && len(step.Actions) > 0 {
			fmt.Fprintf(&result, "\tActions:\n")
			for idx, action := range step.Actions {
				fmt.Fprintf(&result, "\t\t%d. %s\n", idx, nestedGoStringOf(action))
			}
		}
		if len(step.Issues) > 0 {
			fmt.Fprintf(&result, "\tIssues:\n")
			for idx, issue := range step.Issues {
				fmt.Fprintf(&result, "\t\t%d. %s\n", idx, nestedGoStringOf(issue))
			}
		}
	}
	return result.String()
}

func (log Log) GetDataMeasuredWith(trustChain types.TrustChain) []types.MeasuredData {
	var result []types.MeasuredData
	for _, step := range log {
		if len(step.MeasuredData) == 0 {
			continue
		}
		for _, measuredData := range step.MeasuredData {
			if measuredData.TrustChain == trustChain {
				result = append(result, measuredData)
			}
		}
	}

	return result
}
