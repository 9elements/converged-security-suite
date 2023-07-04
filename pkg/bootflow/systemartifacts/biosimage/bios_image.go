package biosimage

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/dmidecode"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
)

var _ types.SystemArtifact = (*BIOSImage)(nil)

// BIOSImage represents the BIOS firmware image.
type BIOSImage struct {
	Content         []byte
	CacheParsed     *uefi.UEFI
	CacheParseError error
	Accessors       map[reflect.Type]any
}

// New returns a new instance of BIOSImage.
func New(content []byte) *BIOSImage {
	return &BIOSImage{Content: content}
}

// NewFromParsed returns a new instance of BIOSImage.
func NewFromParsed(parsed *uefi.UEFI) *BIOSImage {
	return &BIOSImage{Content: parsed.Buf(), CacheParsed: parsed}
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
func (img *BIOSImage) Size() uint64 {
	return uint64(len(img.Content))
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

// DMITable parses the SMBIOS section and returns data as as DMITable.
func (fw *BIOSImage) DMITable() (*dmidecode.DMITable, error) {
	parsed, err := fw.Parse()
	if err != nil {
		return nil, fmt.Errorf("unable to parse the firmware image: %w", err)
	}

	dmiTable, err := dmidecode.DMITableFromFirmware(parsed)
	if err != nil {
		return nil, fmt.Errorf("unable to get DMI data from the firmware: %w", err)
	}

	return dmiTable, nil
}

// Info returns basic BIOS info: vendor, version, release date and revision.
func (fw *BIOSImage) Info() (*dmidecode.BIOSInfo, error) {
	d, err := fw.DMITable()
	if err != nil {
		return nil, err
	}

	info := d.BIOSInfo()
	return &info, nil
}

// String implements fmt.Stringer.
func (img *BIOSImage) String() string {
	return "BIOSImage"
}
