package biosimage

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
)

var _ types.SystemArtifact = (*BIOSImage)(nil)

// BIOSImage represents the BIOS firmware image.
type BIOSImage struct {
	Content         []byte
	CacheParsed     *uefi.UEFI
	CacheParseError error
}

// New returns a new instance of BIOSImage.
func New(content []byte) *BIOSImage {
	return &BIOSImage{Content: content}
}

// Get returns the BIOSImage given a State.
func Get(state *types.State) (*BIOSImage, error) {
	return types.GetSystemArtifactByTypeFromState[*BIOSImage](state)
}

// With gets the BIOSImage from a State and executes the specified callback.
func With(state *types.State, callback func(*BIOSImage) error) error {
	return types.WithSystemArtifact(state, callback)
}

// Size implements types.SystemArtifact.
func (img *BIOSImage) Size() uint {
	return uint(len(img.Content))
}

// ReadAt implements types.SystemArtifact.
func (img *BIOSImage) ReadAt(b []byte, offset int64) (n int, err error) {
	return bytes.NewReader(img.Content).ReadAt(b, offset)
}

// Parse returns a parsed UEFI image.
func (fw *BIOSImage) Parse() (*uefi.UEFI, error) {
	if fw.CacheParsed == nil && fw.CacheParseError == nil {
		fw.CacheParsed, fw.CacheParseError = uefi.ParseUEFIFirmwareBytes(fw.Content)
	}

	return fw.CacheParsed, fw.CacheParseError
}

// String implements fmt.Stringer.
func (img *BIOSImage) String() string {
	return fmt.Sprintf("[%d]byte{}", len(img.Content))
}
