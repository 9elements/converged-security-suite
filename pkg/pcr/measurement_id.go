package pcr

import (
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/pcd"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
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

const (
	MeasurementIDUndefined = MeasurementID(iota)
	MeasurementIDInit
	MeasurementIDPCR0_DATA
	MeasurementIDACMDate
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
	EndOfMeasurementID
)

// IsFake forces to skip this measurement in real PCR value calculation
func (id MeasurementID) IsFake() bool {
	switch id {
	case MeasurementIDUndefined:
		return true
	case MeasurementIDInit:
		return true
	case MeasurementIDPCDFirmwareVendorVersionCode:
		return true
	case MeasurementIDFITPointer:
		return true
	case MeasurementIDFITHeaders:
		return true
	case MeasurementIDDeepAnalysis:
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
	case MeasurementIDPCR0_DATA:
		return "PCR0_DATA"
	case MeasurementIDACMDate:
		return "ACM_date"
	case MeasurementIDACMDateInPlace:
		return "ACM_date_in_place"
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
	}
	return fmt.Sprintf("unknown_measurement_ID_%d", int(id))
}

func (id MeasurementID) PCRIDs() []ID {
	switch id {
	case MeasurementIDInit:
		return []ID{0}
	case MeasurementIDPCR0_DATA:
		return []ID{0}
	case MeasurementIDACMDate:
		return []ID{0}
	case MeasurementIDACMDateInPlace:
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
	}

	return nil
}

// EventLogEventType returns value of "Type" field of the EventLog entry
// associated with the measurement.
func (id MeasurementID) EventLogEventType() *tpmeventlog.EventType {
	switch id {
	case MeasurementIDInit:
		return eventTypePtr(tpmeventlog.EV_NO_ACTION)
	case MeasurementIDPCR0_DATA:
		return eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS)
	case MeasurementIDACMDate:
		return eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS)
	case MeasurementIDACMDateInPlace:
		return eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS)
	case MeasurementIDBIOSStartupModule:
		return eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS)
	case MeasurementIDSCRTMSeparator:
		return eventTypePtr(tpmeventlog.EV_S_CRTM_CONTENTS)
	case MeasurementIDPCDFirmwareVendorVersionData:
		return eventTypePtr(tpmeventlog.EV_S_CRTM_VERSION)
	case MeasurementIDDXE:
		return eventTypePtr(tpmeventlog.EV_POST_CODE)
	case MeasurementIDSeparator:
		return eventTypePtr(tpmeventlog.EV_SEPARATOR)
	}
	return nil
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

		eventType := measurementID.EventLogEventType()
		if eventType == nil {
			continue
		}

		if *eventType != tpmEventType {
			continue
		}

		result = append(result, measurementID)
	}

	return result
}

// DataProvider provides input data for a MeasureFunc.
type DataProvider interface {
	Firmware() Firmware
	FITEntries() []fit.Entry
	PCDData() pcd.ParsedFirmware
}

// MeasureFunc performs a measurement.
type MeasureFunc func(MeasurementConfig, DataProvider) (*Measurement, error)

// MeasureFunc returns the function to be used for the measurement.
func (id MeasurementID) MeasureFunc() MeasureFunc {
	switch id {
	case MeasurementIDInit:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureInit(), nil
		}
	case MeasurementIDPCR0_DATA:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasurePCR0Data(config, provider.FITEntries())
		}
	case MeasurementIDACMDate:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureACMDate(provider.FITEntries())
		}
	case MeasurementIDACMDateInPlace:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureACMDateInPlace(config.PCR0DataIbbDigestHashAlgorithm, provider.FITEntries())
		}
	case MeasurementIDBIOSStartupModule:
		return func(config MeasurementConfig, provider DataProvider) (*Measurement, error) {
			return MeasureBIOSStartupModule(provider.FITEntries())
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

const (
	DataChunkIDUndefined = DataChunkID(iota)
	DataChunkIDBIOSStartup0
	DataChunkIDBIOSStartup1
	DataChunkIDBIOSStartup2
	DataChunkIDBIOSStartup3
	DataChunkIDACMPolicyStatus
	DataChunkIDACMHeaderSVN
	DataChunkIDACMSignature
	DataChunkIDKeyManifestSignature
	DataChunkIDBootPolicyManifestSignature
	DataChunkIDIBBDigest
	EndOfDataChunkID
)

// DataChunkIDBIOSStartup returns DataChunkID corresponding to
// entryIndex-th BIOS Startup entry (accordingly to FIT).
func DataChunkIDBIOSStartup(entryIndex uint) DataChunkID {
	switch entryIndex {
	case 0:
		return DataChunkIDBIOSStartup0
	case 1:
		return DataChunkIDBIOSStartup1
	case 2:
		return DataChunkIDBIOSStartup2
	case 3:
		return DataChunkIDBIOSStartup3
	}
	panic(fmt.Sprintf("should not happen: %v", entryIndex))
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
