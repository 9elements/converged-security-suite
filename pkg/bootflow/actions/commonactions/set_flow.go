package commonactions

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setFlow struct {
	nextFlowFunc   func() types.Flow
	startStepIndex uint
}

func SetFlow(flowFunc func() types.Flow, stepIndex uint) types.Action {
	return &setFlow{
		nextFlowFunc:   flowFunc,
		startStepIndex: stepIndex,
	}
}

func (step *setFlow) Apply(state *types.State) error {
	state.CurrentFlow = step.nextFlowFunc()
	state.CurrentStepIdx = step.startStepIndex
	return nil
}
