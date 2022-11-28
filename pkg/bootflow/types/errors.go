package types

import (
	"fmt"
	"reflect"
)

type ErrNoSubSystem struct {
	SubSystemKey reflect.Type
}

func (err ErrNoSubSystem) Error() string {
	return fmt.Sprintf("no subsystem of type %T found", err.SubSystemKey)
}

func (err ErrNoSubSystem) SubSystemTypeIs(sample SubSystem) bool {
	return err.SubSystemKey == typeMapKey(sample)
}

func (err ErrNoSubSystem) String() string {
	return fmt.Sprintf("ErrNoSubSystem{%s}", err.SubSystemKey.Name())
}

type ErrNoSystemArtifact struct {
	SystemArtifactKey reflect.Type
}

func (err ErrNoSystemArtifact) Error() string {
	return fmt.Sprintf("no system artifact of type %T found", err.SystemArtifactKey)
}

func (err ErrNoSystemArtifact) ErrNoSystemArtifactTypeIs(sample SystemArtifact) bool {
	return err.SystemArtifactKey == typeMapKey(sample)
}

func (err ErrNoSystemArtifact) String() string {
	return fmt.Sprintf("ErrNoSystemArtifact{%s}", err.SystemArtifactKey.Name())
}
