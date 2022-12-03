package pcr

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/pcd"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	amd "github.com/linuxboot/fiano/pkg/amd/manifest"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// Firmware is a parsed firmware image
type Firmware = *uefi.UEFI

// GetMeasurements returns the measurements which should be performed
// to calculate the requested PCR value based on this `firmware`.
func GetMeasurements(
	firmware Firmware,
	pcrID ID,
	opts ...MeasureOption,
) (
	measurements Measurements,
	flow Flow,
	debugInfo map[string]interface{},
	err error,
) {
	config := DefaultMeasurementConfig
	for _, opt := range opts {
		err = opt.Apply(&config)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("unable to apply configuration option: %w", err)
		}
	}

	measurements, flow, debugInfo, err = getMeasurements(pcrID, firmware, config)

	if measurements == nil {
		return
	}

	if config.FindMissingFakeMeasurements {
		missingRanges := findMissingFakeMeasurements(firmware, pcrID, measurements, opts...)
		if len(missingRanges) > 0 {
			measurements = append(measurements,
				NewRangesMeasurement(
					MeasurementIDDeepAnalysis,
					missingRanges,
				),
			)
		}
	}
	return
}

func getMeasurements(
	pcrID ID,
	firmware Firmware,
	config MeasurementConfig,
) (
	Measurements,
	Flow,
	map[string]interface{},
	error,
) {
	resultConfig := config
	debugInfo := map[string]interface{}{
		"config_orig":   config,
		"config_result": &resultConfig,
	}

	// Detect attestation flow
	detectedFlow, detectFlowErr := DetectAttestationFlow(firmware, config.Registers, config.TPMDevice)
	if detectedFlow != FlowAuto {
		debugInfo["detectedAttestationFlow"] = detectedFlow.String()
	}

	if resultConfig.Flow == FlowAuto {
		if detectedFlow == FlowAuto {
			return nil, FlowAuto, nil,
				fmt.Errorf("unable to detect attestation flow (try option manually selecting flow using --flow option): %w", detectFlowErr)
		}
		resultConfig.Flow = detectedFlow
	}

	// Collect measurements
	measurements, warnings, err := newMeasurementsCollector(firmware).CollectMeasurements(pcrID, resultConfig)
	if err != nil {
		err = fmt.Errorf("unable to collect measurements: %w", err)
	}
	debugInfo["warnings"] = (&errors.MultiError{}).Add(warnings, detectFlowErr).ReturnValue()

	return measurements, resultConfig.Flow, debugInfo, err
}

type measurementsCollector struct {
	firmware         Firmware
	fitEntriesResult *[]fit.Entry
	pcdDataResult    pcd.ParsedFirmware
	amdFirmware      *amd.AMDFirmware
	errors           errors.MultiError
	warnings         errors.MultiError
}

func newMeasurementsCollector(firmware Firmware) *measurementsCollector {
	return &measurementsCollector{
		firmware: firmware,
	}
}

func (c *measurementsCollector) Firmware() Firmware {
	return c.firmware
}

func (c *measurementsCollector) FITEntries() []fit.Entry {
	if c.fitEntriesResult != nil {
		return *c.fitEntriesResult
	}

	fitEntries, err := c.firmware.GetFIT()
	if err != nil {
		_ = c.errors.Add(ErrGetFIT{Err: err})
	}
	c.fitEntriesResult = &fitEntries
	return fitEntries
}

func (c *measurementsCollector) PCDData() pcd.ParsedFirmware {
	if c.pcdDataResult != nil {
		return c.pcdDataResult
	}

	pcdData, err := pcd.ParseFirmware(c.firmware)
	if err != nil {
		if pcdData == nil {
			_ = c.warnings.Add(err)
		} else {
			_ = c.errors.Add(err)
		}
	}
	c.pcdDataResult = pcdData
	return pcdData
}

func (c *measurementsCollector) PSPFirmware() *amd.PSPFirmware {
	if c.amdFirmware != nil {
		return c.amdFirmware.PSPFirmware()
	}
	var err error
	amdFirmware, err := amd.NewAMDFirmware(c.firmware)
	if err != nil {
		_ = c.errors.Add(err)
	}
	c.amdFirmware = amdFirmware
	return c.amdFirmware.PSPFirmware()
}

// CollectMeasurements just returns all the measurements for the specified PCR index.
func (c *measurementsCollector) CollectMeasurements(
	pcrIndex ID,
	config MeasurementConfig,
) (result Measurements, warnings error, err error) {
	switch pcrIndex {
	case 0, 1:
	default:
		return nil, nil, &ErrUnknownPCRID{pcrIndex}
	}

	for _, measurementID := range config.Flow.MeasurementIDs().FilterByPCRIndex(pcrIndex) {
		measurements, err := measurementID.MeasureFunc()(config, c)
		if err != nil {
			if measurementID.IsFake() || len(measurements) > 0 {
				_ = c.warnings.Add(ErrCollect{MeasurementID: measurementID, Err: err})
			} else {
				_ = c.errors.Add(ErrCollect{MeasurementID: measurementID, Err: err})
			}
		}

		for _, m := range measurements {
			if m == nil {
				continue
			}
			result = append(result, m)
		}
	}

	return result, c.warnings.ReturnValue(), c.errors.ReturnValue()
}
