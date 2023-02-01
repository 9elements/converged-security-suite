package types

// Condition is an abstract condition.
type Condition interface {
	Check(*State) bool
}
