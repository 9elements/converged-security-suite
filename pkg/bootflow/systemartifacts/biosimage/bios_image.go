package biosimage

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
)

var _ types.SystemArtifact = (*BIOSImage)(nil)

type BIOSImage struct {
	Content         []byte
	CacheParsed     *uefi.UEFI
	CacheParseError error
}

func New(content []byte) *BIOSImage {
	return &BIOSImage{Content: content}
}

func Get(state *types.State) (*BIOSImage, error) {
	return types.GetSystemArtifactByTypeFromState[*BIOSImage](state)
}

func With(state *types.State, callback func(*BIOSImage) error) error {
	return types.WithSystemArtifact(state, callback)
}

func (img *BIOSImage) Size() uint {
	return uint(len(img.Content))
}

func (img *BIOSImage) ReadAt(b []byte, offset int64) (n int, err error) {
	return bytes.NewReader(img.Content).ReadAt(b, offset)
}

func (fw *BIOSImage) Parse() (*uefi.UEFI, error) {
	if fw.CacheParsed == nil && fw.CacheParseError == nil {
		fw.CacheParsed, fw.CacheParseError = uefi.ParseUEFIFirmwareBytes(fw.Content)
	}

	return fw.CacheParsed, fw.CacheParseError
}

func (img *BIOSImage) GoString() string {
	return fmt.Sprintf("[%d]byte{}", len(img.Content))
}
