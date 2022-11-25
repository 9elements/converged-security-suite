package commonsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setFlow struct {
	nextFlowFunc   func(state *types.State) types.Flow
	startStepIndex uint
}

func SetFlow(flowFunc func(state *types.State) types.Flow, stepIndex uint) types.Step {
	return &setFlow{
		nextFlowFunc:   flowFunc,
		startStepIndex: stepIndex,
	}
}

func SetFlowPredefined(flow types.Flow, stepIndex uint) types.Step {
	return &setFlow{
		nextFlowFunc: func(state *types.State) types.Flow {
			return flow
		},
		startStepIndex: stepIndex,
	}
}

func (step *setFlow) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetFlow(step.nextFlowFunc, step.startStepIndex),
	}
}
