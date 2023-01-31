package validator

import "github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"

type ValidatorNoIssues struct{}

var _ Validator = (*ValidatorNoIssues)(nil)

func (ValidatorNoIssues) Validate(l bootengine.Log) Issues {
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
