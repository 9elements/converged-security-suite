package systemartifacts

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

func BIOSFirmwareFunc(state *types.State, fn func(fw *BIOSFirmware) error) error {
	for _, artifact := range state.SystemArtifacts {
		if artifact, ok := artifact.(*BIOSFirmware); ok {
			return fn(artifact)
		}
	}

	return fmt.Errorf("unable to find a BIOS firmware in the list of artifacts")
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
