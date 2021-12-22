package pcr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	amd "github.com/linuxboot/fiano/pkg/amd/manifest"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

// MeasureBIOSDirectoryHeader constructs measurements of BIOS Directory table header
func MeasureBIOSDirectoryHeader(table *amd.BIOSDirectoryTable, biosDirectoryTableRange pkgbytes.Range) (*Measurement, error) {
	if table == nil {
		return nil, fmt.Errorf("empty BIOS Directory Table")
	}
	var id MeasurementID
	switch table.BIOSCookie {
	case amd.BIOSDirectoryTableCookie:
		id = MeasurementIDBIOSDirectoryLevel1Header
	case amd.BIOSDirectoryTableLevel2Cookie:
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

// MeasurePSPDirectoryHeader constructs measurements of PSP Directory table header
func MeasurePSPDirectoryHeader(table *amd.PSPDirectoryTable, pspDirectoryTableRange pkgbytes.Range) (*Measurement, error) {
	if table == nil {
		return nil, fmt.Errorf("empty PSP Directory Table")
	}
	var id MeasurementID
	switch table.PSPCookie {
	case amd.PSPDirectoryTableCookie:
		id = MeasurementIDPSPDirectoryLevel1Header
	case amd.PSPDirectoryTableLevel2Cookie:
		id = MeasurementIDPSPDirectoryLevel2Header
	default:
		return nil, fmt.Errorf("unknown psp table cookie: '%X'", table.PSPCookie)
	}
	headerSize := uint64(binary.Size(table.PSPDirectoryTableHeader))
	if headerSize > pspDirectoryTableRange.Length {
		return nil, fmt.Errorf("psp table is too short: '%d'", pspDirectoryTableRange.Length)
	}
	return NewRangeMeasurement(id, pspDirectoryTableRange.Offset, headerSize), nil
}

// MeasureBIOSDirectoryTable constructs measurements of BIOS Directory table
func MeasureBIOSDirectoryTable(table *amd.BIOSDirectoryTable, biosDirectoryTableRange pkgbytes.Range) (*Measurement, error) {
	if table == nil {
		return nil, fmt.Errorf("empty BIOS Directory Table")
	}

	var id MeasurementID
	switch table.BIOSCookie {
	case amd.BIOSDirectoryTableCookie:
		id = MeasurementIDBIOSDirectoryLevel1
	case amd.BIOSDirectoryTableLevel2Cookie:
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

// MeasurePSPDirectoryTable constructs measurements of PSP Directory table
func MeasurePSPDirectoryTable(table *amd.PSPDirectoryTable, pspDirectoryTableRange pkgbytes.Range) (*Measurement, error) {
	if table == nil {
		return nil, fmt.Errorf("empty PSP Directory Table")
	}

	var id MeasurementID
	switch table.PSPCookie {
	case amd.PSPDirectoryTableCookie:
		id = MeasurementIDPSPDirectoryLevel1
	case amd.PSPDirectoryTableLevel2Cookie:
		id = MeasurementIDPSPDirectoryLevel2
	default:
		return nil, fmt.Errorf("unknown psp table cookie: '%X'", table.PSPCookie)
	}
	headerSize := uint64(binary.Size(table.PSPDirectoryTableHeader))
	if headerSize > pspDirectoryTableRange.Length {
		return nil, fmt.Errorf("psp table is too short: '%d'", pspDirectoryTableRange.Length)
	}

	return NewRangeMeasurement(
		id,
		pspDirectoryTableRange.Offset+headerSize,
		pspDirectoryTableRange.Length-headerSize), nil
}

// MeasureBIOSDirectoryTableEntries constructs measurements of AMD's BIOS directory table entries
func MeasureBIOSDirectoryTableEntries(table *amd.BIOSDirectoryTable) (*Measurement, error) {
	if table == nil {
		return nil, fmt.Errorf("empty BIOS Directory Table")
	}

	var id MeasurementID

	switch table.BIOSCookie {
	case amd.BIOSDirectoryTableCookie:
		id = MeasurementIDBIOSDirectoryLevel1Entries
	case amd.BIOSDirectoryTableLevel2Cookie:
		id = MeasurementIDBIOSDirectoryLevel2Entries
	default:
		return nil, fmt.Errorf("unknown bios table cookie: '%X'", table.BIOSCookie)
	}

	var ranges []pkgbytes.Range
	for _, entry := range table.Entries {
		switch entry.Type {
		case amd.APCBDataEntry: // this can vary
		case amd.APOBBinaryEntry: // this can vary
		default:
			ranges = append(ranges, pkgbytes.Range{Offset: entry.SourceAddress, Length: uint64(entry.Size)})
		}
	}
	return NewRangesMeasurement(id, ranges), nil
}

// MeasurePSPDirectoryTableEntries constructs measurements of AMD's PSP directory table entries
func MeasurePSPDirectoryTableEntries(table *amd.PSPDirectoryTable) (*Measurement, error) {
	if table == nil {
		return nil, fmt.Errorf("empty PSP Directory Table")
	}

	var id MeasurementID

	switch table.PSPCookie {
	case amd.PSPDirectoryTableCookie:
		id = MeasurementIDPSPDirectoryLevel1Entries
	case amd.PSPDirectoryTableLevel2Cookie:
		id = MeasurementIDPSPDirectoryLevel2Entries
	default:
		return nil, fmt.Errorf("unknown psp table cookie: '%X'", table.PSPCookie)
	}

	ranges := []pkgbytes.Range{}

	for _, entry := range table.Entries {
		switch entry.Type {
		case 0x0B: // Skip PSP Soft Fuse Entry
		default:
			ranges = append(ranges, pkgbytes.Range{Offset: entry.LocationOrValue, Length: uint64(entry.Size)})
		}
	}

	return NewRangesMeasurement(id, ranges), nil
}

// MeasureMP0C2PMsgRegisters constructs measurement of AMD's MPO_CP2_MSG registers
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

// MeasurePSPVersion constructs measurement of PSP version
func MeasurePSPVersion(image []byte, pspDirectoryLevel1, pspDirectoryLevel2 *amd.PSPDirectoryTable) (*Measurement, error) {
	for _, pspDirectory := range []*amd.PSPDirectoryTable{pspDirectoryLevel2, pspDirectoryLevel1} {
		if pspDirectory == nil {
			continue
		}

		for _, entry := range pspDirectory.Entries {
			if entry.Type == amd.PSPBootloaderFirmwareEntry {
				h, err := amd.ParsePSPHeader(bytes.NewBuffer(image[entry.LocationOrValue : entry.LocationOrValue+uint64(entry.Size)]))
				if err != nil {
					return nil, fmt.Errorf("failed to parse PSP bootloader header: %w", err)
				}
				return NewRangeMeasurement(MeasurementIDPSPVersion, entry.LocationOrValue+h.VersionOffset(), h.VersionLength()), nil
			}
		}
	}
	return nil, fmt.Errorf("failed to find PSP Bootloader entry")
}

// MeasureEntryFromBIOSDirectory returns measurements of BIOS directory items
// It also does an optional check items count if optCountCheck input arguments is provided
func MeasureEntryFromBIOSDirectory(entryType amd.BIOSDirectoryTableEntryType, optCountCheck *int,
	biosDirectoryLevel1, biosDirectoryLevel2 *amd.BIOSDirectoryTable,
	measurementID MeasurementID,
) (Measurements, error) {
	var foundEntries []amd.BIOSDirectoryTableEntry
	for _, biosDirectory := range []*amd.BIOSDirectoryTable{biosDirectoryLevel2, biosDirectoryLevel1} {
		if biosDirectory == nil {
			continue
		}
		for _, entry := range biosDirectory.Entries {
			if entry.Type == entryType {
				foundEntries = append(foundEntries, entry)
			}
		}
		break
	}

	if optCountCheck != nil && *optCountCheck != len(foundEntries) {
		return nil, fmt.Errorf("expected %d number of %v bios directory items, found: %d",
			*optCountCheck,
			entryType,
			len(foundEntries))
	}

	sort.Slice(foundEntries, func(i, j int) bool {
		return foundEntries[i].Instance < foundEntries[j].Instance
	})

	var result Measurements
	for _, entry := range foundEntries {
		result = append(result, NewRangeMeasurement(measurementID, entry.SourceAddress, uint64(entry.Size)))
	}
	return result, nil
}

func checkPSPFirmwareFound(pspFirmware *amd.PSPFirmware) error {
	if pspFirmware == nil {
		return fmt.Errorf("PSP firmware is not found")
	}
	return nil
}
