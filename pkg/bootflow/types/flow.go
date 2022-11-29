package types

import (
	"fmt"
	"strings"
)

// Flow describes steps of the boot process.
//
// A flow is static (never change).
type Flow []Step

// Step describes a single step of a boot process, essential for the measurements.
// Steps of a flow may vary depending on a State.
//
// An example: measure specific sections in an AMD Manifest
type Step interface {
	Actions(*State) Actions
}

// StaticStep is a Step which has a predefined static list of Actions.
type StaticStep Actions

// Actions implements interface Step.
func (step StaticStep) Actions(*State) Actions {
	return Actions(step)
}

// String implements fmt.Stringer.
func (step StaticStep) String() string {
	var result []string
	for _, action := range step {
		result = append(result, fmt.Sprintf("%v", action))
	}
	return fmt.Sprintf("StaticStep{%s}", strings.Join(result, ", "))
}
