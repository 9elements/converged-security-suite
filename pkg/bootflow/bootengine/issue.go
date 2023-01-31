package bootengine

import "fmt"

// StepIssue is an error returned by a Step.
type StepIssue struct {
	ActionIndex uint
	Issue       error
}

// Error implements the `error` interface.
func (err StepIssue) Error() string {
	return err.Unwrap().Error()
}

// Unwrap enables support of go1.13 error unwrapping.
func (err StepIssue) Unwrap() error {
	return err.Issue
}

func (err StepIssue) String() string {
	return fmt.Sprintf("action#%d: %v", err.ActionIndex, err.Issue)
}

// StepIssues is a slice of StepIssue-s
type StepIssues []StepIssue
