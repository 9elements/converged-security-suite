package commonsteps

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type setActorFromFunc struct {
	nextActorFunc func(state *types.State) types.Actor
}

var _ types.Step = (*setActorFromFunc)(nil)

// SetActorFromFunc sets the Actor depending on the State.
func SetActorFromFunc(actorFunc func(state *types.State) types.Actor) types.Step {
	return &setActorFromFunc{
		nextActorFunc: actorFunc,
	}
}

// Actions implements types.Step.
func (step *setActorFromFunc) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetActorFunc(step.nextActorFunc),
	}
}

type setActor struct {
	nextActor types.Actor
}

// SetActor just sets the Actor.
func SetActor(actor types.Actor) types.Step {
	return &setActor{
		nextActor: actor,
	}
}

// Actions implements types.Step.
func (step *setActor) Actions(state *types.State) types.Actions {
	return types.Actions{
		commonactions.SetActor(step.nextActor),
	}
}

func (step *setActor) String() string {
	return fmt.Sprintf("SetActor(%s)", format.NiceString(step.nextActor))
}
