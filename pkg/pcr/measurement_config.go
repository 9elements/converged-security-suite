package pcr

import (
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

// MeasurementConfig is the structure used to store different gates about
// how the PCR value calculation is performed.
type MeasurementConfig struct {
	// Flow defines which measurements are used to get the final PCR values.
	Flow Flow

	// FindMissingFakeMeasurements defines if there should be performed an
	// additional slow check for ranges which are not added into
	// measurements by default, but may have effect on PCR calculation.
	// And if there were found such ranges they will be added to an
	// additional fake measurement.
	FindMissingFakeMeasurements bool

	// Registers is the status registers. For example register ACM_POLICY_STATUS
	// affects PCR0 value in the CBnT-0T flow.
	Registers registers.Registers

	// PCR0DataIbbDigestHashAlgorithm defines hash algorithm that should be used for pcr0Data.ibbDigest
	// TPM_ALG_ERROR will use the first element (by default)
	PCR0DataIbbDigestHashAlgorithm manifest.Algorithm
}

// DefaultMeasurementConfig defines the default values for MeasurementConfig.
var DefaultMeasurementConfig = MeasurementConfig{
	Flow: FlowAuto,
}
