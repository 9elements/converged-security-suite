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

type setFlow struct {
	nextFlow types.Flow
}

var _ types.Action = (*setFlowFunc)(nil)

// SetFlow sets the Flow.
func SetFlow(flow types.Flow) types.Action {
	return &setFlow{
		nextFlow: flow,
	}
}

// Apply implements types.Action.
func (action *setFlow) Apply(_ context.Context, state *types.State) error {
	state.SetFlow(action.nextFlow)
	return nil
}

func (action *setFlow) String() string {
	nextSteps := action.nextFlow.Steps
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
