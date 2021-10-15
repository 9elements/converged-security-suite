package pcr

import (
	"fmt"

	amd_manifest "github.com/9elements/converged-security-suite/v2/pkg/amd/manifest"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/pcd"
)

func getMeasurementsPCR0(
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
	measurements, warnings, err := newPCR0MeasurementsCollector(firmware).CollectPRC0Measurements(resultConfig)
	if err != nil {
		err = fmt.Errorf("unable to collect measurements: %w", err)
	}
	debugInfo["warnings"] = (&errors.MultiError{}).Add(warnings, detectFlowErr).ReturnValue()

	return measurements, resultConfig.Flow, debugInfo, err
}

type pcr0MeasurementsCollector struct {
	firmware         Firmware
	fitEntriesResult *[]fit.Entry
	pcdDataResult    *pcd.ParsedFirmware
	amdFirmware      *amd_manifest.AMDFirmware
	errors           errors.MultiError
	warnings         errors.MultiError
}

func newPCR0MeasurementsCollector(firmware Firmware) *pcr0MeasurementsCollector {
	return &pcr0MeasurementsCollector{
		firmware: firmware,
	}
}

func (c *pcr0MeasurementsCollector) Firmware() Firmware {
	return c.firmware
}

func (c *pcr0MeasurementsCollector) FITEntries() []fit.Entry {
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

func (c *pcr0MeasurementsCollector) PCDData() pcd.ParsedFirmware {
	if c.pcdDataResult != nil {
		return *c.pcdDataResult
	}

	pcdData, err := pcd.ParseFirmware(c.firmware)
	if err != nil {
		_ = c.errors.Add(err)
	}
	c.pcdDataResult = &pcdData
	return pcdData
}

func (c *pcr0MeasurementsCollector) PSPFirmware() *amd_manifest.PSPFirmware {
	if c.amdFirmware != nil {
		return c.amdFirmware.PSPFirmware()
	}
	var err error
	amdFirmware, err := amd_manifest.NewAMDFirmware(c.firmware)
	if err != nil {
		_ = c.errors.Add(err)
	}
	c.amdFirmware = amdFirmware
	return c.amdFirmware.PSPFirmware()
}

// CollectPRC0Measurements just returns all the measurements
func (c *pcr0MeasurementsCollector) CollectPRC0Measurements(
	config MeasurementConfig,
) (result Measurements, warnings error, err error) {
	for _, measurementID := range config.Flow.MeasurementIDs() {
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
