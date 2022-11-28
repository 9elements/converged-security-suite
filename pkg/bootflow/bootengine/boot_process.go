package bootengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// BootProcess represents an imaginary/virtual process of booting
// a machine. Given a flow it will replay all the expected actions,
// and it will be possible to analyze what happened in result.
type BootProcess struct {
	// Do not mutate these values from the outside, the mutability
	// is owned by BootProcess itself.
	CurrentState *types.State
	Log          Log
}

// NewBootProcess returns a new instance of BootProcess.
func NewBootProcess(state *types.State) *BootProcess {
	return &BootProcess{
		CurrentState: state,
	}
}

func stateNextStep(ctx context.Context, state *types.State) (types.Step, types.Actions, StepIssues, bool) {
	actCoords := &state.CurrentActionCoordinates
	if actCoords.Flow == nil {
		return nil, nil, nil, false
	}

	if actCoords.StepIndex >= uint(len(actCoords.Flow)) {
		return nil, nil, nil, false
	}

	step := actCoords.Flow[actCoords.StepIndex]
	actions := step.Actions(state)
	var stepIssues StepIssues
	for idx, action := range actions {
		actCoords.ActionIndex = uint(idx)
		issue := action.Apply(ctx, state)
		if issue != nil {
			stepIssues = append(stepIssues, StepIssue{ActionIndex: uint(idx), Issue: issue})
		}
	}

	actCoords.StepIndex++
	return step, actions, stepIssues, true
}

// BootProcess executes the current step and switches to pointer to the next step.
func (process *BootProcess) NextStep(ctx context.Context) bool {
	oldMeasuredData := process.CurrentState.MeasuredData
	stepBackend, actions, stepIssues, ok := stateNextStep(ctx, process.CurrentState)
	if !ok {
		return false
	}
	step := StepResult{Step: stepBackend, Actions: actions}
	step.Issues = stepIssues

	if len(process.CurrentState.MeasuredData) > len(oldMeasuredData) {
		step.MeasuredData = process.CurrentState.MeasuredData[len(oldMeasuredData):]
	}

	process.Log = append(process.Log, step)
	return true
}

// Finish executes all the rest steps.
func (process *BootProcess) Finish(ctx context.Context) {
	for process.NextStep(ctx) {
	}
}

// String implements fmt.Stringer.
func (process *BootProcess) String() string {
	var result strings.Builder
	fmt.Fprintf(&result, "Current state:\n\t%s\n", nestedStringOf(process.CurrentState))
	fmt.Fprintf(&result, "Resulting steps:\n\t%s\n", nestedStringOf(process.Log))
	return result.String()
}

func nestedStringOf(i interface{}) string {
	v := fmt.Sprintf("%v", i)
	return strings.ReplaceAll(strings.Trim(v, "\n"), "\n", "\n\t")
}
