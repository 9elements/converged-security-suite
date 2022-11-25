package types

// Flow describes steps of the boot process.
//
// A flow is static (never change).
type Flow []Step

// Stop describes a single step of a boot process, essential for the measurements.
// Steps of a flow may vary depending on a State.
//
// An example: measure specific sections in an AMD Manifest
type Step interface {
	Actions(*State) Actions
}

type StaticStep Actions

func (step StaticStep) Actions(*State) Actions {
	return Actions(step)
}
