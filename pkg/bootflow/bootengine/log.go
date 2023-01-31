package bootengine

import (
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// StepResult is the outcome of a single Step execution.
type StepResult struct {
	Actor        types.Actor
	ActorCode    *types.Data
	Step         types.Step
	Actions      types.Actions
	MeasuredData types.MeasuredDataSlice
	Issues       StepIssues
}

// Log is a slice of StepResult.
type Log []StepResult

// String implements fmt.Stringer.
func (log Log) String() string {
	var result strings.Builder
	for idx, step := range log {
		fmt.Fprintf(&result, "%d. %v:\n", idx, format.NiceString(step.Step))
		if len(step.MeasuredData) > 0 {
			fmt.Fprintf(&result, "\tMeasuredData:\n")
			for idx, measuredData := range step.MeasuredData {
				fmt.Fprintf(&result, "\t\t%d. %s\n", idx, format.NestedStringOf(measuredData))
			}
		}
		if len(step.Actions) > 0 {
			fmt.Fprintf(&result, "\tActions:\n")
			for idx, action := range step.Actions {
				fmt.Fprintf(&result, "\t\t%d. %s\n", idx, format.NestedStringOf(action))
			}
		}
		if len(step.Issues) > 0 {
			fmt.Fprintf(&result, "\tIssues:\n")
			for idx, issue := range step.Issues {
				fmt.Fprintf(&result, "\t\t%d. %s\n", idx, format.NestedStringOf(issue))
			}
		}
	}
	return result.String()
}

// GetDataMeasuredWith returns all the data which was measured.
func (log Log) GetDataMeasuredWith(trustChain types.TrustChain) types.MeasuredDataSlice {
	var result types.MeasuredDataSlice
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
