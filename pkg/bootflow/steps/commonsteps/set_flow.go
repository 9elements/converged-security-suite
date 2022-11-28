package commonsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setFlowFunc struct {
	nextFlowFunc func(state *types.State) types.Flow
}

var _ types.Step = (*setFlowFunc)(nil)

// SetFlow sets the Flow depending on the State.
func SetFlowFromFunc(flowFunc func(state *types.State) types.Flow) types.Step {
	return &setFlowFunc{
		nextFlowFunc: flowFunc,
	}
}

// Action implements types.Step.
func (step *setFlowFunc) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetFlowFunc(step.nextFlowFunc),
	}
}

type setFlow struct {
	nextFlow types.Flow
}

var _ types.Step = (*setFlow)(nil)

// SetFlow just sets the Flow.
func SetFlow(flow types.Flow) types.Step {
	return &setFlow{
		nextFlow: flow,
	}
}

// Action implements types.Step.
func (step *setFlow) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetFlow(step.nextFlow),
	}
}
