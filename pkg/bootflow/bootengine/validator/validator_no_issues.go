package validator

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// ValidatorNoIssues validates if there were no issues while processing the boot flow.
type ValidatorNoIssues struct{}

var _ Validator = (*ValidatorNoIssues)(nil)

// Validate implements Validator.
func (ValidatorNoIssues) Validate(_ context.Context, _ *types.State, l bootengine.Log) Issues {
	var result []Issue
	for stepIdx, step := range l {
		for _, issue := range step.Issues {
			result = append(result, Issue{
				StepIdx:   uint(stepIdx),
				StepIssue: issue,
			})
		}
	}
	return result
}
