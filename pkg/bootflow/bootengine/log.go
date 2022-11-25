package bootengine

import (
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Step struct {
	Step         types.Step
	Actions      types.Actions
	VerifiedData []types.VerifiedData
	Issues       StepIssues
}

type Log []Step

func (log Log) GoString() string {
	var result strings.Builder
	for idx, step := range log {
		fmt.Fprintf(&result, "%d. %#v:\n", idx, step.Step)
		if len(step.VerifiedData) > 0 {
			fmt.Fprintf(&result, "\tVerifiedData:\n")
			for idx, verifiedData := range step.VerifiedData {
				fmt.Fprintf(&result, "\t\t%d. %s\n", idx, nestedGoStringOf(verifiedData))
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

func (log Log) GetDataVerifiedBy(trustChain types.TrustChain) []types.VerifiedData {
	var result []types.VerifiedData
	for _, step := range log {
		if len(step.VerifiedData) == 0 {
			continue
		}
		for _, verifiedData := range step.VerifiedData {
			if verifiedData.TrustChain == trustChain {
				result = append(result, verifiedData)
			}
		}
	}

	return result
}
