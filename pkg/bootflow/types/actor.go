package types

// Actor defines the piece of code responsible for specific Action.
// This might help to validate if no Action is performed from a non-MeasuredData.
type Actor interface {
	// ResponsibleCode is the code which supposedly performs the actions
	// of this Actor.
	ResponsibleCode() DataSource
}
