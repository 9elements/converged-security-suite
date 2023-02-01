package types

import (
	"context"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
)

// Flow describes steps of the boot process.
//
// A flow is static (never change).
type Flow []Step

func (flow Flow) String() string {
	var result strings.Builder
	result.WriteString("{\n")
	for _, step := range flow {
		result.WriteByte('\t')
		result.WriteString(format.NiceString(step))
		result.WriteByte('\n')
	}
	result.WriteString("}\n")
	return result.String()
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
