package types

import (
	"context"
)

// Actions is a slice of Action-s
type Actions []Action

// Action describes a single event happening during some boot step.
//
// In contrast to Step, Action implements low-level operations which mutates the State.
//
// An example: measure a specific section in an AMD Manifest
type Action interface {
	// Apply applies changes to the State.
	Apply(context.Context, *State) error
}

// ActionCoordinates is a set of coordinates, which defines an Action
// within a Flow.
//
// TODO: make serializable
type ActionCoordinates struct {
	// Flow is the Flow where the Action is defined.
	Flow Flow `faker:"flow"`

	// StepIndex is the index of the Step within the Flow.
	StepIndex uint

	// ActionIndex is the index of the Action within the Step.
	ActionIndex uint
}

// Step returns the Step.
func (coords *ActionCoordinates) Step() Step {
	if uint(len(coords.Flow.Steps)) <= coords.StepIndex {
		return nil
	}
	return coords.Flow.Steps[coords.StepIndex]
}

// IsSameStep returns true if the Flow and StepIndex are the same.
func (coords *ActionCoordinates) IsSameStep(cmp ActionCoordinates) bool {
	return coords.Flow.Name == cmp.Flow.Name && coords.StepIndex == cmp.StepIndex
}
