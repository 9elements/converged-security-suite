package commonactions

import (
	"context"

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

func (step *setFlow) Apply(_ context.Context, state *types.State) error {
	state.SetFlow(step.nextFlow)
	return nil
}
