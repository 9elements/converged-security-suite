package pcd

import (
	"bytes"

	"github.com/linuxboot/fiano/pkg/guid"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/pcd/consts"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
)

// "PCD" means "Platform Configuration Database"
//
// See also https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/edkii-platform-config-database-entries-paper.pdf
// (there's no information how to parse it from a firmware, but just some basics of what is PCD are explain)

// Interface is the abstraction over any PCD-values source
type Interface interface {
	// GetFirmwareVendorVersion returns the firmware vendor version value.
	GetFirmwareVendorVersion() []byte
}

// ParsedFirmware is abstraction over PCD-values extracted from a firmware image.
type ParsedFirmware interface {
	Interface

	// GetFirmwareVendorVersionRanges returns ranges which contains the
	// firmware vendor version value.
	GetFirmwareVendorVersionRanges() pkgbytes.Ranges

	// GetFirmwareVendorVersionCodeRanges returns ranges which defines
	// the code which is responsible for the firmware vendor version value.
	GetFirmwareVendorVersionCodeRanges() pkgbytes.Ranges

	// GetFirmwareVendorVersionFFSGUID returns the GUID of the FFS node which
	// was used as the source of the firmware vendor version value.
	GetFirmwareVendorVersionFFSGUID() guid.GUID
}

type ParsedFirmwareGeneric struct {
	FirmwareImage FirmwareImage

	FirmwareVendorVersionRanges     pkgbytes.Ranges
	FirmwareVendorVersionCodeRanges pkgbytes.Ranges
	FirmwareVendorVersionFFSGUID    guid.GUID
}

func (pcd *ParsedFirmwareGeneric) GetFirmwareVendorVersion() []byte {
	return pcd.FirmwareVendorVersionRanges.Compile(pcd.FirmwareImage.ImageBytes())
}

func (pcd *ParsedFirmwareGeneric) GetFirmwareVendorVersionRanges() pkgbytes.Ranges {
	return pcd.FirmwareVendorVersionRanges
}

func (pcd *ParsedFirmwareGeneric) GetFirmwareVendorVersionCodeRanges() pkgbytes.Ranges {
	return pcd.FirmwareVendorVersionCodeRanges
}

func (pcd *ParsedFirmwareGeneric) GetFirmwareVendorVersionFFSGUID() guid.GUID {
	return pcd.FirmwareVendorVersionFFSGUID
}

type FirmwareImage = *uefi.UEFI

// ParseFirmware extracts PCD values from an UEFI firmware.
//
// If "pcd" is not nil and "err" is not nil, then the value was
// successfully parsed, but there was detected a problem (warning).
// If "pcd" is nil, but "err" is not nil, then there occurred an
// error while parsing the value.
func ParseFirmware(firmwareImage FirmwareImage) (pcd ParsedFirmware, err error) {
	for _, parserFunc := range firmwareParsers {
		pcd, err = parserFunc(firmwareImage)
		if pcd != nil || err != nil {
			return
		}
	}

	return nil, &ErrUnknownVendorType{}
}

// firmwareParser is a function to extract PCD values from a firmware image
// And in this sense UEFI images of different vendors are parsed differently.
// So we have multiple parser-functions, each for each vendor.
// If the a parser-function does not recognize the UEFI image as the image
// of it's vendor, then it just returns nil as both values
// (Interfaces and error).
//
// See also "firmwareParsers", "addFirmwareParser()" and
// "parseFirmware()".
type firmwareParser func(firmwareImage FirmwareImage) (ParsedFirmware, error)

// firmwareParsers contains the parsers for known image formats.
// This slice is filled by init() functions of parse_firmware_*.go.
var firmwareParsers []firmwareParser

// addFirmwareParser is the function to add
// an additional firmwareParser for an UEFI image of
// an additional vendor (see parse_firmware_*.go files).
func addFirmwareParser(parserFunc firmwareParser) {
	firmwareParsers = append(firmwareParsers, parserFunc)
}

// See: https://upload.wikimedia.org/wikipedia/commons/thumb/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg/1280px-Portable_Executable_32_bit_Structure_in_SVG_fixed.svg.png
func findPEFileStart(data []byte) (result int) {
	end := len(data) - 0x125
	for result = 0; result < end; result++ {
		if bytes.Compare(data[result:result+2], consts.MZSignature) != 0 {
			continue
		}

		return
	}

	return -1
}
