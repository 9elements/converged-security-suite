package types

import (
	"io"
)

type SystemArtifacts []SystemArtifact

type SystemArtifact interface {
	io.ReaderAt // should never return an error
	Size() uint
}
