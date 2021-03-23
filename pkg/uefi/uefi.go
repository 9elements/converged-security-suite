package uefi

import (
	"bytes"
	"fmt"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/ostools"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
)

func init() {
	// In fiano "FVFileTypePEIM" is disabled due to some problem
	// on recompressing, but we do not recompress anything.
	//
	// And since we want to know module names, we need to parse
	// PEIM files as well.
	fianoUEFI.SupportedFiles[fianoUEFI.FVFileTypePEIM] = true

	// Enable optimizations. Otherwise we consume ~10 times more CPU and RAM.
	// * ReadOnly forces to do not duplicate buffers.
	// * DisableDecompression forces to do not decompress sections, which is
	//   not required anyway for our purposes, since we are interested in
	//   data before decompression (otherwise one bitflip might lead to
	//   a huge hamming distance).
	fianoUEFI.ReadOnly = true
	fianoUEFI.DisableDecompression = true
}

// UEFI is a PCR0-measurements-aware extension over
// "github.com/linuxboot/fiano/pkg/uefi".
type UEFI struct {
	// Node contains the root node of the parsed UEFI structure of the image
	ffs.Node
}

// ParseUEFIFirmwareFile parses the UEFI firmware image by path `imagePath`
func ParseUEFIFirmwareFile(imagePath string) (*UEFI, error) {
	imageBytes, err := ostools.FileToBytes(imagePath)
	if err != nil {
		return nil, fmt.Errorf(`unable to get the content of file "%s": %w`,
			imagePath, err)
	}

	uefi, err := ParseUEFIFirmwareBytes(imageBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse UEFI image file '%s': %w", imagePath, err)
	}

	return uefi, nil
}

// ParseUEFIFirmwareBytes parses the UEFI firmware image from bytes
func ParseUEFIFirmwareBytes(imageBytes []byte) (*UEFI, error) {
	if bytes.HasPrefix(imageBytes, consts.HPSignedFileMagic) {
		// HP signed files starts with a signature and a certificate chain,
		// so we skip it all here...

		realStartIdx := bytes.Index(imageBytes, consts.HPImageMagic)
		if realStartIdx < 0 {
			return nil, &ErrUnableToUnwrapHPSignedFile{}
		}
		imageBytes = imageBytes[realStartIdx:]
	}

	if pkgbytes.IsZeroFilled(imageBytes) {
		return nil, ErrZeroImage{}
	}

	uefi := &UEFI{}

	var err error
	uefi.Firmware, err = fianoUEFI.Parse(imageBytes)
	if err != nil {
		return nil, fmt.Errorf(`unable to parse the UEFI structure of the image: %w`, err)
	}
	uefi.Range.Length = uint64(len(uefi.Buf()))

	return uefi, nil
}

// ImageBytes just returns the image as `[]byte`.
func (uefi *UEFI) ImageBytes() []byte {
	return uefi.Buf()
}

// PhysAddrToOffset returns the offset of `physAddr` relatively
// to the beginning of the firmware.
func (uefi *UEFI) PhysAddrToOffset(physAddr uint64) uint64 {
	startAddr := uint64(consts.BasePhysAddr - len(uefi.ImageBytes()))
	return physAddr - startAddr
}

// OffsetToPhysAddr returns the `physAddr` of offset relatively
// to the beginning of the firmware.
func (uefi *UEFI) OffsetToPhysAddr(offset uint64) uint64 {
	startAddr := uint64(consts.BasePhysAddr - len(uefi.ImageBytes()))
	return offset + startAddr
}

// GetFIT returns parsed FIT-entries
func (uefi *UEFI) GetFIT() ([]fit.Entry, error) {
	return fit.GetEntries(uefi.Buf())
}
