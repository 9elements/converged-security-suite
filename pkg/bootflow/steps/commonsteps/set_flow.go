package commonsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setFlowFunc struct {
	nextFlowFunc func(state *types.State) types.Flow
}

func SetFlowFromFunc(flowFunc func(state *types.State) types.Flow) types.Step {
	return &setFlowFunc{
		nextFlowFunc: flowFunc,
	}
}
func (step *setFlowFunc) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetFlowFunc(step.nextFlowFunc),
	}
}

type setFlow struct {
	nextFlow types.Flow
}

func SetFlow(flow types.Flow) types.Step {
	return &setFlow{
		nextFlow: flow,
	}
}

func (step *setFlow) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetFlow(step.nextFlow),
	}
}
