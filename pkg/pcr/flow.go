package pcr

import (
	"fmt"
	"strings"
)

// Flow defines which measurements are used to get the final PCR values.
type Flow int

func (f Flow) String() string {
	switch f {
	case FlowAuto:
		return "Auto"
	case FlowIntelLegacyTXTDisabled:
		return "LegacyTXTDisabled"
	case FlowIntelLegacyTXTEnabled:
		return "LegacyTXTEnabled"
	case FlowIntelLegacyTXTEnabledTPM12:
		return "LegacyTXTEnabledTPM12"
	case FlowIntelCBnT0T:
		return "CBnT0T"
	}
	panic(fmt.Sprintf("Flow's %d string representation is not supported", f))
}

func FlowFromString(s string) (Flow, error) {
	switch strings.ToLower(s) {
	case "auto":
		return FlowAuto, nil
	case "legacytxtdisabled":
		return FlowIntelLegacyTXTDisabled, nil
	case "legacytxtenabled":
		return FlowIntelLegacyTXTEnabled, nil
	case "legacytxtenabledtpm12":
		return FlowIntelLegacyTXTEnabledTPM12, nil
	case "cbnt0t":
		return FlowIntelCBnT0T, nil
	}
	return FlowAuto, fmt.Errorf("'%s' attestation flow is not supported", s)
}

const (
	// FlowAuto means to guess the flow.
	FlowAuto = Flow(iota)

	// FlowIntelLegacyTXTDisabled means a pre-CBnT flow with disabled TXT.
	FlowIntelLegacyTXTDisabled

	// FlowIntelLegacyTXTEnabled means a pre-CBnT flow with enabled TXT.
	FlowIntelLegacyTXTEnabled

	// FlowIntelCBnT0T means CBnT flow with profile "0T".
	FlowIntelCBnT0T

	// FlowIntelLegacyTXTEnabledTPM12 means a pre-CBnT flow with enabled TXT for TPM 1.2
	FlowIntelLegacyTXTEnabledTPM12
)

// Flows contains all supported PCR measurements flows
var Flows = []Flow{
	FlowAuto,
	FlowIntelLegacyTXTDisabled,
	FlowIntelLegacyTXTEnabled,
	FlowIntelLegacyTXTEnabledTPM12,
	FlowIntelCBnT0T,
}

// TPMLocality returns TPM initialization locality in this flow.
func (f Flow) TPMLocality() uint8 {
	switch f {
	case FlowIntelCBnT0T, FlowIntelLegacyTXTEnabled:
		return 3
	}

	return 0
}

// MeasurementIDs returns which measurements should be performed for in flow.
func (f Flow) MeasurementIDs() MeasurementIDs {
	switch f {
	case FlowIntelCBnT0T:
		/*
			A sample of the EventLog:
			fwtool display_eventlog -pcr-index 0 -hash-algo 4
			  #     idx            typ      hash    digest  data
			  0      0               3        4     0000000000000000000000000000000000000000        537461727475704C6F63616C6974790003                        <- Init
			  1      0               7        4     3FD5F9C9D04E8C604052A3EE838A8D6EB9D598AA        426F6F74204775617264204D6561737572656420532D4352544D00    <- PCR0_DATA
			  3      0               8        4     C42FEDAD268200CB1D15F97841C344E79DAE3320        1EFB6B540C1D5540A4AD4EF4BF17B83A                          <- FirmwareVendorVersionData
			  4      0               1        4     0944F48783C30C8B69A8D1CF07C1BC1823DB6516        000011FF0000000000F0AA0000000000                          <- DXE
			 13      0               4        4     9069CA78E7450A285173431B3E52C5C25299E473        00000000                                                  <- Separator
		*/
		return MeasurementIDs{
			MeasurementIDInit, // is fake measurement
			MeasurementIDPCR0_DATA,
			MeasurementIDPCDFirmwareVendorVersionData,
			MeasurementIDPCDFirmwareVendorVersionCode, // is fake measurement
			MeasurementIDDXE,
			MeasurementIDSeparator,
			MeasurementIDFITPointer, // is fake measurement
			MeasurementIDFITHeaders, // is fake measurement
		}
	case FlowIntelLegacyTXTEnabled:
		// See also:
		// * https://www.trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
		// * https://github.com/openpts/openpts/blob/master/models/uefi_pcr0.uml
		// * https://github.com/openpts/openpts/blob/master/models/bios_pcr0.uml
		// * https://www.trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v21.pdf (Section 9.3.1)
		// * doc/log/ymm03.txt
		return MeasurementIDs{
			MeasurementIDInit, // is fake measurement
			MeasurementIDACMDate,
			MeasurementIDBIOSStartupModule,
			MeasurementIDSCRTMSeparator,
			MeasurementIDPCDFirmwareVendorVersionData,
			MeasurementIDPCDFirmwareVendorVersionCode, // is fake measurement
			MeasurementIDDXE,
			MeasurementIDSeparator,
			MeasurementIDFITPointer, // is fake measurement
			MeasurementIDFITHeaders, // is fake measurement
		}
	case FlowIntelLegacyTXTEnabledTPM12:
		return MeasurementIDs{
			MeasurementIDInit, // is fake measurement
			MeasurementIDACMDateInPlace,
			MeasurementIDBIOSStartupModule,
			MeasurementIDPCDFirmwareVendorVersionData,
			MeasurementIDPCDFirmwareVendorVersionCode, // is fake measurement
			MeasurementIDDXE,
			MeasurementIDSeparator,
			MeasurementIDFITPointer, // is fake measurement
			MeasurementIDFITHeaders, // is fake measurement
		}
	case FlowIntelLegacyTXTDisabled:
		return MeasurementIDs{
			MeasurementIDPCDFirmwareVendorVersionData,
			MeasurementIDPCDFirmwareVendorVersionCode, // is fake measurement
			MeasurementIDDXE,
			MeasurementIDSeparator,

			// Also we include as fake measurements the byte ranges which a known
			// to be necessary to correctly parse the firmware.
			MeasurementIDFITPointer, // is fake measurement
			MeasurementIDFITHeaders, // is fake measurement
		}
	}
	panic(fmt.Sprintf("should not happen: %v", f))
}
