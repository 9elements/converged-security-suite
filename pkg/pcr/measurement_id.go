package pcr

import (
	"fmt"
	"strings"

	amd "github.com/linuxboot/fiano/pkg/amd/manifest"

	"github.com/9elements/converged-security-suite/v2/pkg/pcd"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// MeasurementID is the unique identifier of a PCR measurement.
type MeasurementID int

// MarshalJSON implements json.Marshaler.
func (id MeasurementID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + id.String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (id *MeasurementID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	for candidate := MeasurementID(0); candidate < EndOfMeasurementID; candidate++ {
		if candidate.String() == s {
			*id = candidate
			return nil
		}
	}

	return fmt.Errorf("invalid MeasurementID: '%s'", s)
}

// List of available MeasurementID-s
const (
	MeasurementIDUndefined = MeasurementID(iota)
	MeasurementIDInit
	MeasurementIDPCR0DATA
	MeasurementIDACM
	MeasurementIDACMDate
	MeasurementIDKeyManifest
	MeasurementIDBootPolicyManifest
	MeasurementIDIBBFake
	MeasurementIDBIOSStartupModule
	MeasurementIDSCRTMSeparator
	MeasurementIDPCDFirmwareVendorVersionData
	MeasurementIDPCDFirmwareVendorVersionCode
	MeasurementIDDXE
	MeasurementIDSeparator
	MeasurementIDFITPointer
	MeasurementIDFITHeaders
	MeasurementIDDeepAnalysis
	MeasurementIDACMDateInPlace
	MeasurementIDBIOSDirectoryLevel1
	MeasurementIDBIOSDirectoryLevel1Entries
	MeasurementIDBIOSDirectoryLevel1Header
	MeasurementIDBIOSDirectoryLevel2
	MeasurementIDBIOSDirectoryLevel2Entries
	MeasurementIDBIOSDirectoryLevel2Header
	MeasurementIDPSPDirectoryLevel1
	MeasurementIDPSPDirectoryLevel1Entries
	MeasurementIDPSPDirectoryLevel1Header
	MeasurementIDPSPDirectoryLevel2
	MeasurementIDPSPDirectoryLevel2Entries
	MeasurementIDPSPDirectoryLevel2Header
	MeasurementIDMP0C2PMsgRegisters
	MeasurementIDEmbeddedFirmwareStructure
	MeasurementIDPSPVersion
	MeasurementIDBIOSRTMVolume
	MeasurementIDPMUFirmwareInstructions
	MeasurementIDPMUFirmwareData
	MeasurementIDMicrocodePatch
	MeasurementIDVideoImageInterpreter
	MeasurementIDUnknown
	EndOfMeasurementID
)

// IsFake forces to skip this measurement in real PCR value calculation
func (id MeasurementID) IsFake() bool {
	switch id {
	case MeasurementIDUndefined:
		return true
	case MeasurementIDInit:
		return true
	case MeasurementIDACM:
		return true
	case MeasurementIDKeyManifest:
		return true
	case MeasurementIDBootPolicyManifest:
		return true
	case MeasurementIDIBBFake:
		return true
	case MeasurementIDPCDFirmwareVendorVersionCode:
		return true
	case MeasurementIDFITPointer:
		return true
	case MeasurementIDFITHeaders:
		return true
	case MeasurementIDDeepAnalysis:
		return true
	case MeasurementIDBIOSDirectoryLevel1Entries:
		return true
	case MeasurementIDBIOSDirectoryLevel2Entries:
		return true
	case MeasurementIDPSPDirectoryLevel1:
		return true
	case MeasurementIDPSPDirectoryLevel1Header:
		return true
	case MeasurementIDPSPDirectoryLevel2:
		return true
	case MeasurementIDPSPDirectoryLevel2Header:
		return true
	case MeasurementIDPSPDirectoryLevel1Entries:
		return true
	case MeasurementIDPSPDirectoryLevel2Entries:
		return true
	}

	return false
}

// IsMultiple means that this MeasurementID describes multiple measurements
func (id MeasurementID) IsMultiple() bool {
	switch id {
	case MeasurementIDPMUFirmwareInstructions:
		return true
	case MeasurementIDPMUFirmwareData:
		return true
	case MeasurementIDMicrocodePatch:
		return true
	}
	return false
}

// NoHash forces to skip hashing of this measurement's data during PCR calculation
func (id MeasurementID) NoHash() bool {
	switch id {
	case MeasurementIDACMDateInPlace:
		return true
	}
	return false
}

// String implements fmt.Stringer
func (id MeasurementID) String() string {
	switch id {
	case MeasurementIDUndefined:
		return "undefined"
	case MeasurementIDInit:
		return "init"
	case MeasurementIDACM:
		return "ACM"
	case MeasurementIDPCR0DATA:
		return "PCR0_DATA"
	case MeasurementIDKeyManifest:
		return "key_manifest"
	case MeasurementIDBootPolicyManifest:
		return "boot_policy_manifest"
	case MeasurementIDACMDate:
		return "ACM_date"
	case MeasurementIDACMDateInPlace:
		return "ACM_date_in_place"
	case MeasurementIDIBBFake:
		return "IBB"
	case MeasurementIDBIOSStartupModule:
		return "BIOS_startup_module"
	case MeasurementIDSCRTMSeparator:
		return "S-CRTM_separator"
	case MeasurementIDPCDFirmwareVendorVersionData:
		return "pcdFirmwareVendor_measured_data"
	case MeasurementIDPCDFirmwareVendorVersionCode:
		return "pcdFirmwareVendor_code"
	case MeasurementIDDXE:
		return "DXE"
	case MeasurementIDSeparator:
		return "separator"
	case MeasurementIDFITPointer:
		return "FIT_pointer"
	case MeasurementIDFITHeaders:
		return "FIT_headers"
	case MeasurementIDDeepAnalysis:
		return "deep_analysis"
	case MeasurementIDBIOSDirectoryLevel1Header:
		return "Header of BIOS directory table level 1"
	case MeasurementIDBIOSDirectoryLevel1:
		return "BIOS directory table level 1"
	case MeasurementIDBIOSDirectoryLevel2Header:
		return "Header of BIOS directory table level 2"
	case MeasurementIDBIOSDirectoryLevel2:
		return "BIOS directory table level 2"
	case MeasurementIDBIOSDirectoryLevel1Entries:
		return "Entries of BIOS directory table level 1"
	case MeasurementIDBIOSDirectoryLevel2Entries:
		return "Entries of BIOS directory table level 2"
	case MeasurementIDPSPDirectoryLevel1Header:
		return "Header of PSP directory table level 1"
	case MeasurementIDPSPDirectoryLevel1:
		return "PSP directory table level 1"
	case MeasurementIDPSPDirectoryLevel2Header:
		return "Header of PSP directory table level 2"
	case MeasurementIDPSPDirectoryLevel2:
		return "PSP directory table level 2"
	case MeasurementIDPSPDirectoryLevel1Entries:
		return "Entries of PSP directory table level 1"
	case MeasurementIDPSPDirectoryLevel2Entries:
		return "Entries of PSP directory table level 2"
	case MeasurementIDMP0C2PMsgRegisters:
		return "AMD MP0_CP2MSG registers"
	case MeasurementIDEmbeddedFirmwareStructure:
		return "Embedded Firmware Structure"
	case MeasurementIDPSPVersion:
		return "PSP firmware version"
	case MeasurementIDBIOSRTMVolume:
		return "BIOS RTM Volume"
	case MeasurementIDPMUFirmwareInstructions:
		return "PMU Firmware instructions"
	case MeasurementIDPMUFirmwareData:
		return "PMU Firmware data"
	case MeasurementIDMicrocodePatch:
		return "Microcode patch file"
	case MeasurementIDVideoImageInterpreter:
		return "Interpreter binary that displays the video image"
	}
	return fmt.Sprintf("unknown_measurement_ID_%d", int(id))
}

// PCRIDs returns in which PCRs the measurement is supposed to be used.
//
// Currently we support only PCR0, so everything returns 0 or nil.
func (id MeasurementID) PCRIDs() []ID {
	switch id {
	case MeasurementIDInit:
		return []ID{0}
	case MeasurementIDPCR0DATA:
		return []ID{0}
	case MeasurementIDACM:
		return []ID{0}
	case MeasurementIDACMDate:
		return []ID{0}
	case MeasurementIDACMDateInPlace:
		return []ID{0}
	case MeasurementIDKeyManifest:
		return []ID{0}
	case MeasurementIDBootPolicyManifest:
		return []ID{0}
	case MeasurementIDIBBFake:
		return []ID{0}
	case MeasurementIDBIOSStartupModule:
		return []ID{0}
	case MeasurementIDSCRTMSeparator:
		return []ID{0}
	case MeasurementIDPCDFirmwareVendorVersionData:
		return []ID{0}
	case MeasurementIDPCDFirmwareVendorVersionCode:
		return []ID{0}
	case MeasurementIDDXE:
		return []ID{0}
	case MeasurementIDSeparator:
		return []ID{0}
	case MeasurementIDFITPointer:
		return []ID{0}
	case MeasurementIDFITHeaders:
		return []ID{0}
	case MeasurementIDDeepAnalysis:
		return []ID{0}
	case MeasurementIDBIOSDirectoryLevel1Header:
		return []ID{0}
	case MeasurementIDBIOSDirectoryLevel1:
		return []ID{0}
	case MeasurementIDBIOSDirectoryLevel2Header:
		return []ID{0}
	case MeasurementIDBIOSDirectoryLevel2:
		return []ID{0}
	case MeasurementIDMP0C2PMsgRegisters:
		return []ID{0}
	case MeasurementIDEmbeddedFirmwareStructure:
		return []ID{0}
	case MeasurementIDPSPVersion:
		return []ID{0}
	case MeasurementIDBIOSRTMVolume:
		return []ID{0}
	case MeasurementIDPMUFirmwareInstructions:
		return []ID{0}
	case MeasurementIDPMUFirmwareData:
		return []ID{0}
	case MeasurementIDMicrocodePatch:
		return []ID{0}
	case MeasurementIDVideoImageInterpreter:
		return []ID{0}
	}
	return nil
}

// EventLogEventTypes returns multiple potential values of "Type" field of the EventLog entry
// associated with the measurement.
func (id MeasurementID) EventLogEventTypes() []*tpmeventlog.EventType {
	var eventTypes []*tpmeventlog.EventType
	switch id {
	case MeasurementIDInit:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_NO_ACTION))
	case MeasurementIDPCR0DATA:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS))
	case MeasurementIDACMDate:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS))
	case MeasurementIDACMDateInPlace:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS))
	case MeasurementIDBIOSStartupModule:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS))
	case MeasurementIDSCRTMSeparator:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS))
	case MeasurementIDPCDFirmwareVendorVersionData:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_S_CRTM_VERSION))
	case MeasurementIDDXE:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_POST_CODE))
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2))
	case MeasurementIDSeparator:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_SEPARATOR))
	case MeasurementIDBIOSDirectoryLevel1Header:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDBIOSDirectoryLevel1:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDBIOSDirectoryLevel2Header:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDBIOSDirectoryLevel2:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDMP0C2PMsgRegisters:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDEmbeddedFirmwareStructure:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDPSPVersion:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDBIOSRTMVolume:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDPMUFirmwareInstructions:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDPMUFirmwareData:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	case MeasurementIDVideoImageInterpreter:
		eventTypes = append(eventTypes, eventTypePtr(tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB))
	}
	return eventTypes
}

// TPMEventTypeToMeasurementIDs returns all measurement ID-s which could be
// represented with specified EventType for a specified PCR index.
func TPMEventTypeToMeasurementIDs(pcrID ID, tpmEventType tpmeventlog.EventType) MeasurementIDs {
	var result MeasurementIDs

	for measurementID := MeasurementIDUndefined; measurementID < EndOfMeasurementID; measurementID++ {
		foundPCRID := false
		for _, cmp := range measurementID.PCRIDs() {
			if cmp == pcrID {
				foundPCRID = true
				break
			}
		}
		if !foundPCRID {
			continue
		}

		eventTypes := measurementID.EventLogEventTypes()

		if len(eventTypes) == 0 {
			continue
		}

		for _, eventType := range eventTypes {
			if *eventType == tpmEventType {
				result = append(result, measurementID)
			}
		}
	}

	return result
}

// DataProvider provides input data for a MeasureFunc.
type DataProvider interface {
	Firmware() Firmware
	FITEntries() []fit.Entry
	PCDData() pcd.ParsedFirmware
	PSPFirmware() *amd.PSPFirmware
}

// MeasureFunc performs a measurement.
type MeasureFunc func(MeasurementConfig, DataProvider) (Measurements, error)

type singleMeasureFunc func(MeasurementConfig, DataProvider) (*Measurement, error)

// MeasureFunc returns the function to be used for the measurement.
func (id MeasurementID) MeasureFunc() MeasureFunc {
	if id.IsMultiple() {
		return id.multipleMeasureFunc()
	}
	measureFunc := id.singleMeasureFunc()
	if measureFunc == nil {
		return nil
	}
	return func(config MeasurementConfig, provider DataProvider) (Measurements, error) {
		m, err := measureFunc(config, provider)
		if err != nil {
			return nil, err
		}
		return Measurements{m}, err
	}
}

func (id MeasurementID) singleMeasureFunc() singleMeasureFunc {
	switch id {
	case MeasurementIDInit:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureInit(), nil
		}
	case MeasurementIDPCR0DATA:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasurePCR0Data(config, uint64(len(provider.Firmware().Buf())), provider.FITEntries())
		}
	case MeasurementIDKeyManifest:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureKeyManifest(uint64(len(provider.Firmware().Buf())), provider.FITEntries())
		}
	case MeasurementIDBootPolicyManifest:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureBootPolicy(uint64(len(provider.Firmware().Buf())), provider.FITEntries())
		}
	case MeasurementIDACM:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureACM(uint64(len(provider.Firmware().Buf())), provider.FITEntries())
		}
	case MeasurementIDACMDate:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureACMDate(uint64(len(provider.Firmware().Buf())), provider.FITEntries())
		}
	case MeasurementIDACMDateInPlace:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureACMDateInPlace(config.PCR0DataIbbDigestHashAlgorithm, uint64(len(provider.Firmware().Buf())), provider.FITEntries())
		}
	case MeasurementIDIBBFake:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureIBB(provider.FITEntries(), uint64(len(provider.Firmware().Buf())))
		}
	case MeasurementIDBIOSStartupModule:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureBIOSStartupModule(uint64(len(provider.Firmware().Buf())), provider.FITEntries())
		}
	case MeasurementIDSCRTMSeparator:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureSCRTMSeparator(), nil
		}
	case MeasurementIDPCDFirmwareVendorVersionData:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasurePCDFirmwareVendorVersionData(provider.PCDData())
		}
	case MeasurementIDPCDFirmwareVendorVersionCode:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasurePCDFirmwareVendorVersionCode(provider.PCDData())
		}
	case MeasurementIDDXE:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureDXE(provider.Firmware())
		}
	case MeasurementIDSeparator:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureSeparator(), nil
		}
	case MeasurementIDFITPointer:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureFITPointer(provider.Firmware()), nil
		}
	case MeasurementIDFITHeaders:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureFITHeaders(provider.Firmware())
		}
	case MeasurementIDBIOSDirectoryLevel1Header:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureBIOSDirectoryHeader(pspFirmware.BIOSDirectoryLevel1, pspFirmware.BIOSDirectoryLevel1Range)
		}
	case MeasurementIDBIOSDirectoryLevel2Header:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureBIOSDirectoryHeader(pspFirmware.BIOSDirectoryLevel2, pspFirmware.BIOSDirectoryLevel2Range)
		}
	case MeasurementIDBIOSDirectoryLevel1:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureBIOSDirectoryTable(pspFirmware.BIOSDirectoryLevel1, pspFirmware.BIOSDirectoryLevel1Range)
		}
	case MeasurementIDBIOSDirectoryLevel2:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureBIOSDirectoryTable(pspFirmware.BIOSDirectoryLevel2, pspFirmware.BIOSDirectoryLevel2Range)
		}

	case MeasurementIDBIOSDirectoryLevel1Entries:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureBIOSDirectoryTableEntries(pspFirmware.BIOSDirectoryLevel1)
		}

	case MeasurementIDBIOSDirectoryLevel2Entries:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureBIOSDirectoryTableEntries(pspFirmware.BIOSDirectoryLevel2)
		}

	case MeasurementIDPSPDirectoryLevel1Header:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasurePSPDirectoryHeader(pspFirmware.PSPDirectoryLevel1, pspFirmware.PSPDirectoryLevel1Range)
		}
	case MeasurementIDPSPDirectoryLevel2Header:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasurePSPDirectoryHeader(pspFirmware.PSPDirectoryLevel2, pspFirmware.PSPDirectoryLevel2Range)
		}
	case MeasurementIDPSPDirectoryLevel1:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasurePSPDirectoryTable(pspFirmware.PSPDirectoryLevel1, pspFirmware.PSPDirectoryLevel1Range)
		}
	case MeasurementIDPSPDirectoryLevel2:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasurePSPDirectoryTable(pspFirmware.PSPDirectoryLevel2, pspFirmware.PSPDirectoryLevel2Range)
		}

	case MeasurementIDPSPDirectoryLevel1Entries:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasurePSPDirectoryTableEntries(pspFirmware.PSPDirectoryLevel1)
		}

	case MeasurementIDPSPDirectoryLevel2Entries:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasurePSPDirectoryTableEntries(pspFirmware.PSPDirectoryLevel2)
		}

	case MeasurementIDMP0C2PMsgRegisters:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureMP0C2PMsgRegisters(config.Registers)
		}

	case MeasurementIDEmbeddedFirmwareStructure:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return NewRangeMeasurement(
				MeasurementIDEmbeddedFirmwareStructure,
				pspFirmware.EmbeddedFirmwareRange.Offset,
				pspFirmware.EmbeddedFirmwareRange.Length), nil
		}

	case MeasurementIDPSPVersion:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			firmware := provider.Firmware()
			return MeasurePSPVersion(firmware.ImageBytes(), pspFirmware.PSPDirectoryLevel1, pspFirmware.PSPDirectoryLevel2)
		}

	case MeasurementIDBIOSRTMVolume:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			expectedInstancesCount := 1
			measurements, err := MeasureEntryFromBIOSDirectory(amd.BIOSRTMVolumeEntry, &expectedInstancesCount,
				pspFirmware.BIOSDirectoryLevel1, pspFirmware.BIOSDirectoryLevel2, MeasurementIDBIOSRTMVolume)
			var result *Measurement
			if len(measurements) > 0 {
				result = measurements[0]
			}
			return result, err
		}
	case MeasurementIDVideoImageInterpreter:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			expectedInstancesCount := 1
			measurements, err := MeasureEntryFromBIOSDirectory(amd.VideoInterpreterEntry, &expectedInstancesCount,
				pspFirmware.BIOSDirectoryLevel1, pspFirmware.BIOSDirectoryLevel2, MeasurementIDVideoImageInterpreter)
			var result *Measurement
			if len(measurements) > 0 {
				result = measurements[0]
			}
			return result, err
		}
	}
	return nil
}

func (id MeasurementID) multipleMeasureFunc() MeasureFunc {
	switch id {
	case MeasurementIDPMUFirmwareInstructions:
		return func(config MeasurementConfig, provider DataProvider) (Measurements, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureEntryFromBIOSDirectory(amd.PMUFirmwareInstructionsEntry, nil,
				pspFirmware.BIOSDirectoryLevel1, pspFirmware.BIOSDirectoryLevel2, MeasurementIDPMUFirmwareInstructions)
		}
	case MeasurementIDPMUFirmwareData:
		return func(config MeasurementConfig, provider DataProvider) (Measurements, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureEntryFromBIOSDirectory(amd.PMUFirmwareDataEntry, nil,
				pspFirmware.BIOSDirectoryLevel1, pspFirmware.BIOSDirectoryLevel2, MeasurementIDPMUFirmwareData)
		}
	case MeasurementIDMicrocodePatch:
		return func(config MeasurementConfig, provider DataProvider) (Measurements, error) {
			pspFirmware := provider.PSPFirmware()
			if err := checkPSPFirmwareFound(pspFirmware); err != nil {
				return nil, err
			}
			return MeasureEntryFromBIOSDirectory(amd.MicrocodePatchEntry, nil,
				pspFirmware.BIOSDirectoryLevel1, pspFirmware.BIOSDirectoryLevel2, MeasurementIDMicrocodePatch)
		}
	}
	return nil
}

// MeasurementIDs is a set of MeasurementID-s
type MeasurementIDs []MeasurementID

// Contains returns true if the slice contains measurement ID `id`.
func (s MeasurementIDs) Contains(id MeasurementID) bool {
	for _, item := range s {
		if item == id {
			return true
		}
	}
	return false
}

// FilterByPCRIndex returns a subset of measurement IDs only which corresponds to specified PCR index.
func (s MeasurementIDs) FilterByPCRIndex(pcrIndex ID) MeasurementIDs {
	var r MeasurementIDs
	for _, m := range s {
		found := false
		for _, pcrIndexCmp := range m.PCRIDs() {
			if pcrIndexCmp == pcrIndex {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		r = append(r, m)
	}

	return r
}

// DataChunkID is an unique identified of the measured data chunk
type DataChunkID int

// MarshalJSON implements json.Marshaler.
func (id DataChunkID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + id.String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (id *DataChunkID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	for candidate := DataChunkID(0); candidate < EndOfDataChunkID; candidate++ {
		if candidate.String() == s {
			*id = candidate
			return nil
		}
	}

	return fmt.Errorf("invalid DataChunkID: '%s'", s)
}

// The list of available DataChunkID-s
const (
	DataChunkIDUndefined = DataChunkID(iota)
	DataChunkIDBIOSStartup0
	DataChunkIDBIOSStartup1
	DataChunkIDBIOSStartup2
	DataChunkIDBIOSStartup3
	DataChunkIDBIOSStartup4
	DataChunkIDBIOSStartup5
	DataChunkIDACMPolicyStatus
	DataChunkIDACMHeaderSVN
	DataChunkIDACMSignature
	DataChunkIDKeyManifestSignature
	DataChunkIDBootPolicyManifestSignature
	DataChunkIDIBBDigest
	DataChunkIDUnknown
	EndOfDataChunkID
)

// DataChunkIDBIOSStartup returns DataChunkID corresponding to
// entryIndex-th BIOS Startup entry (accordingly to FIT).
func DataChunkIDBIOSStartup(entryIndex uint) (DataChunkID, error) {
	switch entryIndex {
	case 0:
		return DataChunkIDBIOSStartup0, nil
	case 1:
		return DataChunkIDBIOSStartup1, nil
	case 2:
		return DataChunkIDBIOSStartup2, nil
	case 3:
		return DataChunkIDBIOSStartup3, nil
	case 4:
		return DataChunkIDBIOSStartup4, nil
	case 5:
		return DataChunkIDBIOSStartup5, nil
	}
	return DataChunkIDUndefined, fmt.Errorf("invalid DataChunkIDBIOSStartup: %v", entryIndex)
}

// String implements fmt.Stringer
func (id DataChunkID) String() string {
	switch id {
	case DataChunkIDUndefined:
		return "undefined"
	case DataChunkIDBIOSStartup0:
		return "BIOS_startup_module_0"
	case DataChunkIDBIOSStartup1:
		return "BIOS_startup_module_1"
	case DataChunkIDBIOSStartup2:
		return "BIOS_startup_module_2"
	case DataChunkIDBIOSStartup3:
		return "BIOS_startup_module_3"
	case DataChunkIDBIOSStartup4:
		return "BIOS_startup_module_4"
	case DataChunkIDBIOSStartup5:
		return "BIOS_startup_module_5"
	case DataChunkIDACMPolicyStatus:
		return "ACM_policy_status"
	case DataChunkIDACMHeaderSVN:
		return "ACM_header_SVN"
	case DataChunkIDACMSignature:
		return "ACM_signature"
	case DataChunkIDKeyManifestSignature:
		return "key_manifest_signature"
	case DataChunkIDBootPolicyManifestSignature:
		return "boot_policy_manifest_signature"
	case DataChunkIDIBBDigest:
		return "IBB_digest"
	}
	return fmt.Sprintf("unknown_data_chunk_ID_%d", int(id))
}
