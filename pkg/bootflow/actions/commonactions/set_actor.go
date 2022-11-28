package commonactions

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setActorFunc struct {
	nextActorFunc func(state *types.State) types.Actor
}

var _ types.Action = (*setActorFunc)(nil)

// SetActorFunc sets the Actor (of the further actions) given a function,
// which returns an actor expected for a specific State.
func SetActorFunc(nextActorFunc func(state *types.State) types.Actor) types.Action {
	return &setActorFunc{
		nextActorFunc: nextActorFunc,
	}
}

func (step *setActorFunc) Apply(_ context.Context, state *types.State) error {
	state.CurrentActor = step.nextActorFunc(state)
	return nil
}

type setActor struct {
	nextActor types.Actor
}

var _ types.Action = (*setActorFunc)(nil)

// SetActor sets the Actor (of the further actions).
func SetActor(nextActor types.Actor) types.Action {
	return &setActor{
		nextActor: nextActor,
	}
}

// Apply implements types.Action.
func (step *setActor) Apply(_ context.Context, state *types.State) error {
	state.CurrentActor = step.nextActor
	return nil
}
