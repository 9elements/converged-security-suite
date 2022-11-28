package bootengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type BootProcess struct {
	// Do not mutate these values from the outside, the mutability
	// is owned by BootProcess itself.
	CurrentState *types.State
	Log          Log
}

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

func (process *BootProcess) NextStep(ctx context.Context) bool {
	oldMeasuredData := process.CurrentState.MeasuredData
	stepBackend, actions, stepIssues, ok := stateNextStep(ctx, process.CurrentState)
	if !ok {
		return false
	}
	step := Step{Step: stepBackend, Actions: actions}
	step.Issues = stepIssues

	if len(process.CurrentState.MeasuredData) > len(oldMeasuredData) {
		step.MeasuredData = process.CurrentState.MeasuredData[len(oldMeasuredData):]
	}

	process.Log = append(process.Log, step)
	return true
}

func (process *BootProcess) Finish(ctx context.Context) {
	for process.NextStep(ctx) {
	}
}

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
