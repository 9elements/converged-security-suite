package pcr

import (
	"encoding/binary"
	"fmt"
	amd_manifest "github.com/9elements/converged-security-suite/v2/pkg/amd/manifest"
	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
)

// MeasureBIOSDirectoryHeader constructs measurements of BIOS Directory table header
func MeasureBIOSDirectoryHeader(table *amd_manifest.BIOSDirectoryTable, biosDirectoryTableRange pkgbytes.Range) (*Measurement, error) {
	if table == nil {
		return nil, nil
	}
	var id MeasurementID
	switch table.BIOSCookie {
	case amd_manifest.BIOSDirectoryTableCookie:
		id = MeasurementIDBIOSDirectoryLevel1Header
	case amd_manifest.BIOSDirectoryTableLevel2Cookie:
		id = MeasurementIDBIOSDirectoryLevel2Header
	default:
		return nil, fmt.Errorf("unknown bios table cookie: '%X'", table.BIOSCookie)
	}
	headerSize := uint64(binary.Size(table.BIOSDirectoryTableHeader))
	if headerSize > biosDirectoryTableRange.Length {
		return nil, fmt.Errorf("bios table is too short: '%d'", biosDirectoryTableRange.Length)
	}
	return NewRangeMeasurement(id, biosDirectoryTableRange.Offset, headerSize), nil
}

// MeasureBIOSDirectoryTable constructs measurements of BIOS Directory table
func MeasureBIOSDirectoryTable(table *amd_manifest.BIOSDirectoryTable, biosDirectoryTableRange pkgbytes.Range) (*Measurement, error) {
	if table == nil {
		return nil, nil
	}

	var id MeasurementID
	switch table.BIOSCookie {
	case amd_manifest.BIOSDirectoryTableCookie:
		id = MeasurementIDBIOSDirectoryLevel1
	case amd_manifest.BIOSDirectoryTableLevel2Cookie:
		id = MeasurementIDBIOSDirectoryLevel2
	default:
		return nil, fmt.Errorf("unknown bios table cookie: '%X'", table.BIOSCookie)
	}
	headerSize := uint64(binary.Size(table.BIOSDirectoryTableHeader))
	if headerSize > biosDirectoryTableRange.Length {
		return nil, fmt.Errorf("bios table is too short: '%d'", biosDirectoryTableRange.Length)
	}
	return NewRangeMeasurement(
		id,
		biosDirectoryTableRange.Offset+headerSize,
		biosDirectoryTableRange.Length-headerSize), nil
}
