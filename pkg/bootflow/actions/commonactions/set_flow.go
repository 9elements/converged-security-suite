package commonactions

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setFlow struct {
	nextFlowFunc   func(state *types.State) types.Flow
	startStepIndex uint
}

var _ types.Action = (*setFlow)(nil)

func SetFlow(flowFunc func(state *types.State) types.Flow, stepIndex uint) types.Action {
	return &setFlow{
		nextFlowFunc:   flowFunc,
		startStepIndex: stepIndex,
	}
}

func (step *setFlow) Apply(_ context.Context, state *types.State) error {
	state.SetFlow(step.nextFlowFunc(state), step.startStepIndex)
	return nil
}
