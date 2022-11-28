package commonsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setActor struct {
	nextActorFunc func(state *types.State) types.Actor
}

func SetActorFromFunc(actorFunc func(state *types.State) types.Actor) types.Step {
	return &setActor{
		nextActorFunc: actorFunc,
	}
}

func SetActor(actor types.Actor) types.Step {
	return &setActor{
		nextActorFunc: func(state *types.State) types.Actor {
			return actor
		},
	}
}

func (step *setActor) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetActor(step.nextActorFunc),
	}
}
