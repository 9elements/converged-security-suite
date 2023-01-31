package bootengine

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
)

type StepIssueCoords any

type StepIssueCoordsActor struct{}

func (StepIssueCoordsActor) String() string {
	return "actor"
}

type StepIssueCoordsAction struct {
	ActionIndex uint
}

func (i StepIssueCoordsAction) String() string {
	return fmt.Sprintf("action#%d", i.ActionIndex)
}

// StepIssue is an error returned by a Step.
type StepIssue struct {
	Coords StepIssueCoords
	Issue  error
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
	return fmt.Sprintf("%s: %v", format.NiceString(err.Coords), err.Issue)
}

// StepIssues is a slice of StepIssue-s
type StepIssues []StepIssue
