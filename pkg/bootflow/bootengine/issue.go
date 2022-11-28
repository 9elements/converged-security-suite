package bootengine

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

// StepIssues is a slice of StepIssue-s
type StepIssues []StepIssue
