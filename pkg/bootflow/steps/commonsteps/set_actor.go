package commonsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setActor struct {
	nextActorFunc func(state *types.State) types.Actor
}

var _ types.Step = (*setActor)(nil)

// SetActorFromFunc sets the Actor depending on the State.
func SetActorFromFunc(actorFunc func(state *types.State) types.Actor) types.Step {
	return &setActor{
		nextActorFunc: actorFunc,
	}
}

// SetActor just sets the Actor.
func SetActor(actor types.Actor) types.Step {
	return &setActor{
		nextActorFunc: func(state *types.State) types.Actor {
			return actor
		},
	}
}

// Actions implements types.Step.
func (step *setActor) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetActorFunc(step.nextActorFunc),
	}
}
