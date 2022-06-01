package bootengine

import (
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

func stateNextStep(state *types.State) (types.Step, types.Actions, StepIssues, bool) {
	if state.CurrentFlow == nil {
		return nil, nil, nil, false
	}

	if state.CurrentStepIdx >= uint(len(state.CurrentFlow)) {
		return nil, nil, nil, false
	}

	step := state.CurrentFlow[state.CurrentStepIdx]
	actions := step.Actions(state)
	var stepIssues StepIssues
	for idx, action := range actions {
		issue := action.Apply(state)
		if issue != nil {
			stepIssues = append(stepIssues, StepIssue{ActionIndex: uint(idx), Issue: issue})
		}
	}

	state.CurrentStepIdx++
	return step, actions, stepIssues, true
}

func (process *BootProcess) NextStep() bool {
	oldVerifiedData := process.CurrentState.VerifiedData
	stepBackend, actions, stepIssues, ok := stateNextStep(process.CurrentState)
	if !ok {
		return false
	}
	step := Step{Step: stepBackend, Actions: actions}
	step.Issues = stepIssues

	if len(process.CurrentState.VerifiedData) > len(oldVerifiedData) {
		step.VerifiedData = process.CurrentState.VerifiedData[len(oldVerifiedData):]
	}

	process.Log = append(process.Log, step)
	return true
}

func (process *BootProcess) Finish() {
	for process.NextStep() {
	}
}

func (process *BootProcess) GoString() string {
	var result strings.Builder
	fmt.Fprintf(&result, "Current state:\n\t%s\n", nestedGoStringOf(process.CurrentState))
	fmt.Fprintf(&result, "Resulting steps:\n\t%s\n", nestedGoStringOf(process.Log))
	return result.String()
}

func nestedGoStringOf(i interface{}) string {
	v := fmt.Sprintf("%#v", i)
	return strings.ReplaceAll(strings.Trim(v, "\n"), "\n", "\n\t")
}
