package types

import (
	"fmt"
	"io"
	"reflect"
	"strings"
)

// SystemArtifacts is a collection of SystemArtifact-s with unique types.
type SystemArtifacts map[reflect.Type]SystemArtifact

// SystemArtifact is an abstract data artifact of the emulated system.
//
// Examples: BIOS firmware image, TXT status registers, MSR registers, PRoT firmware image.
type SystemArtifact interface {
	io.ReaderAt // should never return an error
	Size() uint64
}

// String implements fmt.Stringer.
func (m SystemArtifacts) String() string {
	var result strings.Builder
	for k, artifact := range m {
		fmt.Fprintf(&result, "%s:\n\t%s\n", k.Name(), nestedStringOf(artifact))
	}
	return result.String()
}

func nestedStringOf(i interface{}) string {
	v := fmt.Sprintf("%v", i)
	return strings.ReplaceAll(strings.Trim(v, "\n"), "\n", "\n\t")
}
