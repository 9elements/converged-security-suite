package types

type Actions []Action

// Action describes a single event happening during some boot step.
//
// An example: measure a specific section in an AMD Manifest
type Action interface {
	Apply(*State) error
}

// ActionMeasure is a sub-type of an Action, which specifically
// performs a measurement.
type ActionMeasure interface {
	Action
	MeasuredData() MeasuredData
}

type ActionCoordinates struct {
	Flow        Flow
	StepIndex   uint
	ActionIndex uint
}

func (coords *ActionCoordinates) Step() Step {
	return coords.Flow[coords.StepIndex]
}

func (coords *ActionCoordinates) Action(state *State) Action {
	step := coords.Step()
	return step.Actions(state)[coords.ActionIndex]
}
