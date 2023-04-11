package types

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
)

// Flow describes steps of the boot process.
type Flow struct {
	// Name is the unique name of the Flow.
	//
	// Equivalence of Name-s between two flows should guarantee the equivalence
	// of Steps.
	Name string

	// Steps returns the list of Step-s implied by this flow.
	Steps Steps
}

// NewFlow returns a Flow.
func NewFlow(name string, steps Steps) Flow {
	return Flow{
		Name:  name,
		Steps: steps,
	}
}

// Step describes a single step of a boot process, essential for the measurements.
// Steps of a flow may vary depending on a State.
//
// In contrast to Action, Step just answers the question "what to do", but does not execute it.
//
// An example: measure specific sections in an AMD Manifest
type Step interface {
	Actions(context.Context, *State) Actions
}

// Steps is a slice of Step-s.
type Steps []Step

func (s Steps) String() string {
	var result strings.Builder
	result.WriteString("{\n")
	for _, step := range s {
		result.WriteByte('\t')
		result.WriteString(format.NiceString(step))
		result.WriteByte('\n')
	}
	result.WriteString("}\n")
	return result.String()
}

var _ Step = StaticStep(nil)

// StaticStep is a Step which has a predefined static list of Actions.
type StaticStep Actions

// Actions implements interface Step.
func (step StaticStep) Actions(context.Context, *State) Actions {
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
