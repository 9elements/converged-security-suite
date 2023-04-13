package commonsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
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
func (step *setFlowFunc) Actions(_ context.Context, state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetFlowFunc(step.nextFlowFunc),
	}
}

// SetFlowStruct is the value returned by SetFlow.
type SetFlowStruct struct {
	NextFlow types.Flow
}

var _ types.Step = (*SetFlowStruct)(nil)

// SetFlow returns a types.Step, which just sets the Flow.
func SetFlow(flow types.Flow) types.Step {
	return &SetFlowStruct{
		NextFlow: flow,
	}
}

// Action implements types.Step.
func (step *SetFlowStruct) Actions(_ context.Context, state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetFlow(step.NextFlow),
	}
}

// String implements fmt.Stringer.
func (step *SetFlowStruct) String() string {
	return format.NiceString(step.Actions(context.Background(), nil)[0])
}
