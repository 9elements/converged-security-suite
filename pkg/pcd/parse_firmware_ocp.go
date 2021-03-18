package pcd

import (
	"encoding/hex"
	"fmt"

	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

func init() {
	addFirmwareParser(ParseFirmwareOCP)
}

var (
	ocpVendorVersion = unhex("1EFB6B540C1D5540A4AD4EF4BF17B83A")
)

func unhex(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}

// ParseFirmwareOCP is a variant of ParseFirmware for OCP firmwares
func ParseFirmwareOCP(
	firmwareImage FirmwareImage,
) (ParsedFirmware, error) {
	err := errors.MultiError{}

	generic, errGeneric := parseFirmwareOCPGeneric(firmwareImage)
	err.Add(errGeneric)
	if generic != nil {
		return generic, err.ReturnValue()
	}

	// If non of the parser above recognized the format then
	// `err.ReturnValue()` will be `nil`. But if somebody
	// recognized the format, but failed to parse it, then
	// we will return the error.
	return nil, err.ReturnValue()
}

type ParsedFirmwareOCPGeneric struct {
	ParsedFirmwareGeneric
}

func (pcd *ParsedFirmwareOCPGeneric) GetFirmwareVendorVersion() []byte {
	// Basically we know that in the most cases an OCP firmware has
	// value "1EFB6B540C1D5540A4AD4EF4BF17B83A", so if we were unable
	// to find the real value, we just fallback to this known value.
	//
	// The end-user will be notified about it. Since
	// `pcd.FirmwareVendorVersionRanges` is nil, `GetPCRMeasurements` will
	// return both: measurements and an error. And the end-tool will print
	// both the error and measurements. Here how it may look like:
	//
	//   $ go run ./cmd/pcr0tool/ sum -quiet firmware.bin
	//   GetPCRMeasurements error: errors: unable to find the source of firmware vendor version
	//   5BB1C2692F42A60FB6B0F40717503E1E5E6564C5

	if pcd.FirmwareVendorVersionRanges != nil {
		return pcd.ParsedFirmwareGeneric.GetFirmwareVendorVersion()
	}

	// Fallback to the default value:
	v := make([]byte, len(ocpVendorVersion))
	copy(v, ocpVendorVersion)
	return v
}

func parseFirmwareOCPGeneric(
	firmwareImage FirmwareImage,
) (*ParsedFirmwareOCPGeneric, error) {
	sourceGUID := ffsConsts.GUIDAmiTcgPlatformPeiAfterMem
	nodes, err := firmwareImage.GetByGUID(sourceGUID)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the firmware: %w", err)
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	if len(nodes) > 1 {
		return nil, &ErrTooManyAmiTcgPlatformPeiAfterMems{}
	}
	node := nodes[0]
	return &ParsedFirmwareOCPGeneric{
		ParsedFirmwareGeneric: ParsedFirmwareGeneric{
			FirmwareImage: firmwareImage,
			FirmwareVendorVersionCodeRanges: pkgbytes.Ranges{{
				Offset: node.Offset,
				Length: uint64(len(node.Buf())),
			}},
			FirmwareVendorVersionFFSGUID: sourceGUID,
		},
	}, nil
}
