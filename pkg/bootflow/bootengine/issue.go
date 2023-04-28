package bootengine

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
)

// StepIssueCoords helps to find a specific place where an issue occurred,
// within a types.Step.
//
// Currently may contain either StepIssueCoordsActor or StepIssueCoordsAction.
type StepIssueCoords any

// StepIssueCoordsActor implies that the issue happened during
// execution of Actor-specific logic (currently it is only method `ResponsibleCode`).
type StepIssueCoordsActor struct{}

// String implements fmt.Stringer.
func (StepIssueCoordsActor) String() string {
	return "actor"
}

// StepIssueCoordsAction implies that the issue happened during execution
// of an action with the defined index (the positional number within the types.Step).
type StepIssueCoordsAction struct {
	ActionIndex uint
}

// String implements fmt.Stringer.
func (i StepIssueCoordsAction) String() string {
	return fmt.Sprintf("action#%d", i.ActionIndex)
}

// StepIssueCoordsAction implies that the issue happened during
// getting Actions from the Step.
type StepIssueCoordsActions struct{}

// String implements fmt.Stringer.
func (i StepIssueCoordsActions) String() string {
	return fmt.Sprintf("step->actions")
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

// String implements fmt.Stringer.
func (err StepIssue) String() string {
	return fmt.Sprintf("%s: %v", format.NiceString(err.Coords), err.Issue)
}

// StepIssues is a slice of StepIssue-s
type StepIssues []StepIssue
