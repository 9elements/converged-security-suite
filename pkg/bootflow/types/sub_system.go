package types

import (
	"fmt"
	"reflect"
	"strings"
)

// SubSystem is a collection of SubSystem-s with unique types.
type SubSystems map[reflect.Type]SubSystem

// SubSystem is an abstract subsystem of the imaginary/virtual machine, we imitate
// to boot.
//
// Examples: TPM-backed measured boot, RDMA
type SubSystem interface {
	IsInitialized() bool
}

// String implements fmt.Stringer.
func (m SubSystems) String() string {
	var result strings.Builder
	for k, artifact := range m {
		fmt.Fprintf(&result, "%s:\n\t%s\n", k.Name(), nestedStringOf(artifact))
	}
	return result.String()
}
