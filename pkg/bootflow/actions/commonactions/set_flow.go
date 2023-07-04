package commonactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setFlowFunc struct {
	nextFlowFunc func(state *types.State) types.Flow
}

var _ types.Action = (*setFlowFunc)(nil)

// SetFlowFunc sets the Flow given a function, which returns a Flow expected for a specific State.
func SetFlowFunc(flowFunc func(state *types.State) types.Flow) types.Action {
	return &setFlowFunc{
		nextFlowFunc: flowFunc,
	}
}

// Apply implements types.Action.
func (step *setFlowFunc) Apply(_ context.Context, state *types.State) error {
	state.SetFlow(step.nextFlowFunc(state))
	return nil
}

type SetFlowStruct struct {
	NextFlow types.Flow
}

var _ types.Action = (*SetFlowStruct)(nil)

// SetFlow sets the Flow.
func SetFlow(flow types.Flow) types.Action {
	return &SetFlowStruct{
		NextFlow: flow,
	}
}

// Apply implements types.Action.
func (action *SetFlowStruct) Apply(_ context.Context, state *types.State) error {
	state.SetFlow(action.NextFlow)
	return nil
}

func (action *SetFlowStruct) String() string {
	nextSteps := action.NextFlow.Steps
	if len(nextSteps) == 0 {
		return "SetFlow({})"
	}
	firstStepEnding := ""
	firstStep := format.NiceString(nextSteps[0])
	if len(firstStep) > 40 {
		firstStepEnding = "..."
	}
	if len(nextSteps) == 1 {
		return fmt.Sprintf("SetFlow({%.40s%s})", firstStep, firstStepEnding)
	}
	return fmt.Sprintf("SetFlow({%.40s%s, ...})", firstStep, firstStepEnding)
}
