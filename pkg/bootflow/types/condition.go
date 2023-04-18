package types

import "context"

// Condition is an abstract condition.
type Condition interface {
	Check(context.Context, *State) bool
}
