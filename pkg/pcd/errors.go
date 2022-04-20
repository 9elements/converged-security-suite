package pcd

import (
	"fmt"
	"strings"
)

// ErrTooManyTCGPEIModules means there's more than one TCG PEI module, which is
// not supported (an unknown case).
type ErrTooManyTCGPEIModules struct{}

func (err *ErrTooManyTCGPEIModules) Error() string {
	return `[HP signed file] too many TCG PEI modules`
}

// ErrTcgPieUnableToFindPcdFirmwareVendorStart means it was unable to find
// the beginning of the PCD firmware vendor value within the TCG PIE module.
type ErrTcgPieUnableToFindPcdFirmwareVendorStart struct{}

func (err *ErrTcgPieUnableToFindPcdFirmwareVendorStart) Error() string {
	return `[HP signed file] unable to find the beginning of the pcdFirmwareVendor`
}

// ErrHPPcdFirmwareVendorEndNotFound means it was unable to find the end
// of the PCD firmware vendor value.
type ErrHPPcdFirmwareVendorEndNotFound struct{}

func (err *ErrHPPcdFirmwareVendorEndNotFound) Error() string {
	return `[HP signed file] pcdFirmwareVendor end not found`
}

// ErrInvalidTCGPEIModule means it was unable to parse the TCG PEI module volume
// (it appears to be of unexpected/unknown type).
type ErrInvalidTCGPEIModule struct{}

func (err *ErrInvalidTCGPEIModule) Error() string {
	return `[HP signed file] invalid TcgPei module`
}

// ErrTcgPiePEFileNotFound means it was unable to find the beginning of the
// PE file (which contains the PCD firmware vendor value).
type ErrTcgPiePEFileNotFound struct{}

func (err *ErrTcgPiePEFileNotFound) Error() string {
	return `[HP signed file] PE32 file not found`
}

// ErrDoesNotMatch means a value was received with multiple ways, but the
// value does not match (while it should've).
type ErrDoesNotMatch struct {
	A []byte
	B []byte
}

func (err *ErrDoesNotMatch) Error() string {
	if len(err.A) != len(err.B) {
		return "the length does not match"
	}
	var diff []string
	for idx := range err.A {
		if err.A[idx] == err.B[idx] {
			continue
		}
		if len(diff) > 10 {
			diff = append(diff, "and more...")
			break
		}

		diff = append(diff, fmt.Sprintf("A[%d] (%d) != B[%d] (%d)",
			idx, err.A[idx], idx, err.B[idx]))
	}
	return fmt.Sprintf(`the content does not match: %v (%x != %x)`, strings.Join(diff, ", "), err.A, err.B)
}

// ErrTooManyAmiTcgPlatformPeiAfterMems means multiple AmiTcgPlatformPeiAfterMem
// volume, which is not supported (an unknown case)
type ErrTooManyAmiTcgPlatformPeiAfterMems struct{}

func (err *ErrTooManyAmiTcgPlatformPeiAfterMems) Error() string {
	return "too many AmiTcgPlatformPeiAfterMem volumes"
}

// ErrInvalidAmiTcgPlatformPeiAfterMem means it was unable to parse the
// AmiTcgPlatformPeiAfterMem volume (it appears to be of unexpected/unknown
// type).
type ErrInvalidAmiTcgPlatformPeiAfterMem struct{}

func (err *ErrInvalidAmiTcgPlatformPeiAfterMem) Error() string {
	return "invalid volume AmiTcgPlatformPeiAfterMem"
}

// ErrAmiTcgPlatformPeiAfterMemPEFileNotFound means it was unable to find the
// beginning of the PE file (which contains the PCD firmware vendor value).
type ErrAmiTcgPlatformPeiAfterMemPEFileNotFound struct{}

func (err *ErrAmiTcgPlatformPeiAfterMemPEFileNotFound) Error() string {
	return "[AmiTcgPlatformPeiAfterMem] unable to find the PE file"
}

// ErrAmiTcgPlatformPeiAfterMemUnableToFindPcdFirmwareVendorStart means it
// was unable to find the beginning of the PCD firmware vendor value.
type ErrAmiTcgPlatformPeiAfterMemUnableToFindPcdFirmwareVendorStart struct{}

func (err *ErrAmiTcgPlatformPeiAfterMemUnableToFindPcdFirmwareVendorStart) Error() string {
	return "[AmiTcgPlatformPeiAfterMem] unable to find the pcdFirmwareVendor beginning"
}

// ErrUnknownVendorType means the vendor type is not supported
type ErrUnknownVendorType struct{}

func (err *ErrUnknownVendorType) Error() string {
	return "unable to find an appropriate PCD parser for the firmware image"
}

// ErrTooDummyFirmwareVersionFiles means there were found too many files
// with the GUID used exclusively in dummy firmwares we invented. There
// should be only one such file in a dummy firmware.
type ErrTooDummyFirmwareVersionFiles struct{}

func (err *ErrTooDummyFirmwareVersionFiles) Error() string {
	return "too many version files of a dummy firmware"
}

// ErrDummyFirmwareVersionFileWrongType means the version file of a dummy
// firmware is not a file.
type ErrDummyFirmwareVersionFileWrongType struct{}

func (err *ErrDummyFirmwareVersionFileWrongType) Error() string {
	return "version file of a dummy firmware is not a file"
}
