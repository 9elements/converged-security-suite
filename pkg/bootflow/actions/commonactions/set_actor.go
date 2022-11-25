package commonactions

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setActor struct {
	nextActorFunc func(state *types.State) types.Actor
}

var _ types.Action = (*setActor)(nil)

func SetActor(nextActorFunc func(state *types.State) types.Actor) types.Action {
	return &setActor{
		nextActorFunc: nextActorFunc,
	}
}

func (step *setActor) Apply(state *types.State) error {
	state.CurrentActor = step.nextActorFunc(state)
	return nil
}
