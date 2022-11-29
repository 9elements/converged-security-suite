package types

import (
	"fmt"
	"reflect"
)

// ErrNoSubSystem means the requested SubSystem type was not included into the State.
//
// See also `(*State).IncludeSubSystem()`.
type ErrNoSubSystem struct {
	SubSystemKey reflect.Type
}

// Error implements interface `error`.
func (err ErrNoSubSystem) Error() string {
	return fmt.Sprintf("no subsystem of type %T found", err.SubSystemKey)
}

// SubSystemTypeIs returns true if the underlying type of the provided sample
// is the same as of the requested SubSystem (which was not included to the State).
func (err ErrNoSubSystem) SubSystemTypeIs(sample SubSystem) bool {
	return err.SubSystemKey == typeMapKey(sample)
}

// String implements fmt.Stringer.
func (err ErrNoSubSystem) String() string {
	return fmt.Sprintf("ErrNoSubSystem{%s}", err.SubSystemKey.Name())
}

// ErrNoSystemArtifact means the requested SystemArtifact type was not included
// to the State.
//
// See also `(*State).IncludeSystemArtifact()`.
type ErrNoSystemArtifact struct {
	SystemArtifactKey reflect.Type
}

// Error implements interface `error`.
func (err ErrNoSystemArtifact) Error() string {
	return fmt.Sprintf("no system artifact of type %T found", err.SystemArtifactKey)
}

// SystemArtifactTypeIs returns true if the underlying type of the provided sample
// is the same as of the requested SystemArtifact (which was not included to the State).
func (err ErrNoSystemArtifact) SystemArtifactTypeIs(sample SystemArtifact) bool {
	return err.SystemArtifactKey == typeMapKey(sample)
}

// String implements fmt.Stringer.
func (err ErrNoSystemArtifact) String() string {
	return fmt.Sprintf("ErrNoSystemArtifact{%s}", err.SystemArtifactKey.Name())
}
