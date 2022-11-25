package types

import (
	"fmt"
	"io"
	"reflect"
	"strings"
)

type SystemArtifacts map[reflect.Type]SystemArtifact

type SystemArtifact interface {
	io.ReaderAt // should never return an error
	Size() uint
}

func (m SystemArtifacts) GoString() string {
	var result strings.Builder
	for k, artifact := range m {
		fmt.Fprintf(&result, "%s:\n\t%s\n", k.Name(), nestedGoStringOf(artifact))
	}
	return result.String()
}

func nestedGoStringOf(i interface{}) string {
	v := fmt.Sprintf("%#v", i)
	return strings.ReplaceAll(strings.Trim(v, "\n"), "\n", "\n\t")
}