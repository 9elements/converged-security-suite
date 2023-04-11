package bootengine

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
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

func stateNextStep(
	ctx context.Context,
	state *types.State,
) (
	*types.Data,
	types.Step,
	types.Actions,
	StepIssues,
	bool,
) {
	actCoords := &state.CurrentActionCoordinates
	if actCoords.Flow.Steps == nil {
		return nil, nil, nil, nil, false
	}

	if actCoords.StepIndex >= uint(len(actCoords.Flow.Steps)) {
		return nil, nil, nil, nil, false
	}

	var stepIssues StepIssues

	step := actCoords.Flow.Steps[actCoords.StepIndex]
	actCoords.StepIndex++
	actions := step.Actions(ctx, state)
	for idx, action := range actions {
		actCoords.ActionIndex = uint(idx)
		state.CurrentAction = action
		issue := func() (issue error) {
			defer func() {
				if r := recover(); r != nil {
					stackTrace := debug.Stack()
					if e, ok := r.(error); ok {
						issue = fmt.Errorf("got a panic: %w:\n%s", e, stackTrace)
					} else {
						issue = fmt.Errorf("got a panic: %v:\n%s", r, stackTrace)
					}
				}
			}()
			issue = action.Apply(ctx, state)
			return
		}()
		if issue != nil {
			stepIssues = append(stepIssues, StepIssue{
				Coords: StepIssueCoordsAction{
					ActionIndex: uint(idx),
				},
				Issue: issue,
			})
		}
	}

	var actorCode *types.Data
	if state.CurrentActor != nil {
		if actorCodeSource := state.CurrentActor.ResponsibleCode(); actorCodeSource != nil {
			var err error
			actorCode, err = actorCodeSource.Data(ctx, state)
			if err != nil {
				stepIssues = append(stepIssues, StepIssue{
					Coords: StepIssueCoordsActor{},
					Issue:  err,
				})
			}
		}
	}

	return actorCode, step, actions, stepIssues, true
}

// BootProcess executes the current step and switches to pointer to the next step.
func (process *BootProcess) NextStep(ctx context.Context) bool {
	oldMeasuredData := process.CurrentState.MeasuredData
	actorCode, stepBackend, actions, stepIssues, ok := stateNextStep(ctx, process.CurrentState)
	if !ok {
		return false
	}
	step := StepResult{
		Actor:     process.CurrentState.CurrentActor,
		ActorCode: actorCode,
		Step:      stepBackend,
		Actions:   actions,
		Issues:    stepIssues,
	}

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
	fmt.Fprintf(&result, "Current state:\n\t%s\n", format.NestedStringOf(process.CurrentState))
	fmt.Fprintf(&result, "Resulting steps:\n\t%s\n", format.NestedStringOf(process.Log))
	return result.String()
}
