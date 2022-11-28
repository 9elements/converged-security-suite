package types

import (
	"context"
)

// Actions is a slice of Action-s
type Actions []Action

// Action describes a single event happening during some boot step.
//
// An example: measure a specific section in an AMD Manifest
type Action interface {
	// Apply applies changes to the State.
	Apply(context.Context, *State) error
}

// ActionCoordinates is a set of coordinates, which defines an Action
// within a Flow.
type ActionCoordinates struct {
	// Flow is the Flow where the Action is defined.
	Flow Flow

	// StepIndex is the index of the Step within the Flow.
	StepIndex uint

	// ActionIndex is the index of the Action within the Step.
	ActionIndex uint
}

// Step returns the Step.
func (coords *ActionCoordinates) Step() Step {
	return coords.Flow[coords.StepIndex]
}

// Action returns the Action.
func (coords *ActionCoordinates) Action(state *State) Action {
	step := coords.Step()
	return step.Actions(state)[coords.ActionIndex]
}
