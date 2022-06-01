package biosfirmware

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
)

var _ types.SystemArtifact = (*BIOSFirmware)(nil)

type BIOSFirmware struct {
	Content         []byte
	CacheParsed     *uefi.UEFI
	CacheParseError error
}

func NewBIOSFirmware(content []byte) *BIOSFirmware {
	return &BIOSFirmware{Content: content}
}

func FromState(state *types.State, fn func(fw *BIOSFirmware) error) error {
	return state.SystemArtifactExec((*BIOSFirmware)(nil), func(artifact types.SystemArtifact) error {
		return fn(artifact.(*BIOSFirmware))
	})
}

func (fw *BIOSFirmware) Size() uint {
	return uint(len(fw.Content))
}

func (fw *BIOSFirmware) ReadAt(b []byte, offset int64) (n int, err error) {
	return bytes.NewReader(fw.Content).ReadAt(b, offset)
}

func (fw *BIOSFirmware) Parse() (*uefi.UEFI, error) {
	if fw.CacheParsed == nil && fw.CacheParseError == nil {
		fw.CacheParsed, fw.CacheParseError = uefi.ParseUEFIFirmwareBytes(fw.Content)
	}

	return fw.CacheParsed, fw.CacheParseError
}

func (fw *BIOSFirmware) GoString() string {
	return fmt.Sprintf("[%d]byte{}", len(fw.Content))
}
