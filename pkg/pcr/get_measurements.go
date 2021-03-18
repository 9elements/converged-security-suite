package pcr

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
)

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

	switch pcrID {
	case 0:
		measurements, flow, debugInfo, err = getMeasurementsPCR0(firmware, config)
	default:
		return nil, 0, nil, &ErrUnknownPCRID{pcrID}
	}

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
