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
func MeasurePSPVersion(image []byte, pspFirmware *amd_manifest.PSPFirmware) (Measurements, error) {
	if err := checkPSPFirmwareFound(pspFirmware); err != nil {
		return nil, err
	}
	if pspFirmware.PSPDirectoryLevel2 == nil {
		return nil, fmt.Errorf("PSP directory level 2 is not found")
	}

	for _, entry := range pspFirmware.PSPDirectoryLevel2.Entries {
		if entry.Type == amd_manifest.PSPBootloaderFirmwareEntry {
			h, err := amd_manifest.ParsePSPHeader(bytes.NewBuffer(image[entry.LocationOrValue : entry.LocationOrValue+uint64(entry.Size)]))
			if err != nil {
				return nil, fmt.Errorf("failed to parse PSP bootloader header: '%w'", err)
			}
			return Measurements{NewRangeMeasurement(MeasurementIDPSPVersion, entry.LocationOrValue+h.VersionOffset(), h.VersionLength())}, nil
		}
	}
	return nil, fmt.Errorf("failed to find PSP Bootloader entry")
}

// MeasureBIOSRTMVolume constructs measurement of BIOS RTM Volume
func MeasureBIOSRTMVolume(pspFirmware *amd_manifest.PSPFirmware) (Measurements, error) {
	return collectBIOSDirectoryMeasurements(
		pspFirmware,
		amd_manifest.BIOSRTMVolumeEntry,
		MeasurementIDBIOSRTMVolume,
		true,
	)
}

// MeasurePMUFirmwareInstructions constructs measurements of all PMU firmware instruction entries found in BIOS Directory
func MeasurePMUFirmwareInstructions(pspFirmware *amd_manifest.PSPFirmware) (Measurements, error) {
	return collectBIOSDirectoryMeasurements(pspFirmware,
		amd_manifest.PMUFirmwareInstructionsEntry, MeasurementIDPMUFirmwareInstructions, false)
}

// MeasurePMUFirmwareData constructs measurements of all PMU firmware data entries found in BIOS Directory
func MeasurePMUFirmwareData(pspFirmware *amd_manifest.PSPFirmware) (Measurements, error) {
	return collectBIOSDirectoryMeasurements(pspFirmware,
		amd_manifest.PMUFirmwareDataEntry, MeasurementIDPMUFirmwareData, false)
}

// MeasureMicrocodePatch constructs measurements of all microcode patch entries found in BIOS Directory
func MeasureMicrocodePatch(pspFirmware *amd_manifest.PSPFirmware) (Measurements, error) {
	return collectBIOSDirectoryMeasurements(pspFirmware,
		amd_manifest.MicrocodePatchEntry, MeasurementIDMicrocodePatch, false)
}

// MeasureVideoImageInterpreterBinary constructs measurements of all video image interpreter binaries entries found in BIOS Directory
func MeasureVideoImageInterpreterBinary(pspFirmware *amd_manifest.PSPFirmware) (Measurements, error) {
	return collectBIOSDirectoryMeasurements(pspFirmware,
		amd_manifest.VideoInterpreterBinaryEntry, MeasurementIDVideoImageInterpreter, false)
}

func checkPSPFirmwareFound(pspFirmware *amd_manifest.PSPFirmware) error {
	if pspFirmware == nil {
		return fmt.Errorf("PSP firmware is not found")
	}
	return nil
}

func collectBIOSDirectoryMeasurements(
	pspFirmware *amd_manifest.PSPFirmware,
	entryType amd_manifest.BIOSDirectoryTableEntryType,
	measurementID MeasurementID,
	checkSingle bool,
) (Measurements, error) {
	if err := checkPSPFirmwareFound(pspFirmware); err != nil {
		return nil, fmt.Errorf("PSP firmware is not found")
	}
	if pspFirmware.BIOSDirectoryLevel2 == nil {
		return nil, fmt.Errorf("bios directory level 2 is not found")
	}

	var result Measurements
	for _, entry := range pspFirmware.BIOSDirectoryLevel2.Entries {
		if entry.Type == entryType {
			result = append(result, NewRangeMeasurement(measurementID, entry.SourceAddress, uint64(entry.Size)))
		}
	}
	if checkSingle {
		if len(result) == 0 {
			return nil, fmt.Errorf("failed to find '%s'", entryType.String())
		}
		if len(result) > 1 {
			return nil, fmt.Errorf("multiple entries of '%s' are found", entryType.String())
		}
	}
	return result, nil
}
