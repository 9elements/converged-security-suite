package bootengine

type StepIssue struct {
	ActionIndex uint
	Issue       error
}

func (err StepIssue) Error() string {
	return err.Unwrap().Error()
}

func (err StepIssue) Unwrap() error {
	return err.Issue
}

type StepIssues []StepIssue
