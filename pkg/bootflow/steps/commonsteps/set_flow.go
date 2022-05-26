package commonsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setFlow struct {
	nextFlowFunc   func() types.Flow
	startStepIndex uint
}

func SetFlow(flowFunc func() types.Flow, stepIndex uint) types.Step {
	return &setFlow{
		nextFlowFunc:   flowFunc,
		startStepIndex: stepIndex,
	}
}

func (step *setFlow) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetFlow(step.nextFlowFunc, step.startStepIndex),
	}
}
