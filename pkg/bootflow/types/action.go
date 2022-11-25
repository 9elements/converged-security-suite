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
