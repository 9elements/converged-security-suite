package types

type Condition interface {
	Check(*State) bool
}
