package pcr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	amd_manifest "github.com/9elements/converged-security-suite/v2/pkg/amd/manifest"
	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
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

// MeasureMP0C2PMsgRegisters constructs measurement of AMD's MPO_CP@_MSG registers
func MeasureMP0C2PMsgRegisters(regs registers.Registers) (*Measurement, error) {
	msg37, found := registers.FindMP0C2PMsg37(regs)
	if !found {
		return nil, fmt.Errorf("'%s' is not found", registers.MP0C2PMSG37RegisterID)
	}
	msg38, found := registers.FindMP0C2PMsg38(regs)
	if !found {
		return nil, fmt.Errorf("'%s' is not found", registers.MP0C2PMSG38RegisterID)
	}
	result := bytes.NewBuffer(nil)
	if err := binary.Write(result, binary.LittleEndian, msg37.Raw()); err != nil {
		return nil, err
	}
	if err := binary.Write(result, binary.LittleEndian, msg38.Raw()); err != nil {
		return nil, err
	}
	return NewStaticDataMeasurement(MeasurementIDMP0C2PMsgRegisters, result.Bytes()), nil
}
