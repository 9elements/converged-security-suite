package pcr

import (
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/google/go-tpm/tpm2"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest"
)

// MeasureOption is the interface of an option which may change
// the behavior of how PCR measurements are performed
type MeasureOption interface {
	Apply(*MeasurementConfig) error
}

// SetFlow overrides the measurements flow.
type SetFlow Flow

// Apply implements `MeasureOption`
func (opt SetFlow) Apply(config *MeasurementConfig) error {
	config.Flow = Flow(opt)
	return nil
}

// SetIBBHashDigest allows to override IBBDigest that will be used for CBnT0T Pcr0Data.ibbDigest
type SetIBBHashDigest tpm2.Algorithm

// Apply implements `MeasureOption`
func (opt SetIBBHashDigest) Apply(config *MeasurementConfig) error {
	config.PCR0DataIbbDigestHashAlgorithm = manifest.Algorithm(opt)
	return nil
}

// SetFindMissingFakeMeasurements defines if there should be performed an
// additional slow check for ranges which are not added into
// measurements by default, but may have effect on PCR calculation.
// And if there were found such ranges they will be added to an
// additional fake measurement.
type SetFindMissingFakeMeasurements bool

// Apply implements `MeasureOption`
func (opt SetFindMissingFakeMeasurements) Apply(config *MeasurementConfig) error {
	config.FindMissingFakeMeasurements = bool(opt)
	return nil
}

// SetRegisters sets the status registers
type SetRegisters registers.Registers

// Apply implements `MeasureOption`
func (opt SetRegisters) Apply(config *MeasurementConfig) error {
	config.Registers = registers.Registers(opt)
	return nil
}

// SetTPMDevice sets the TPM type.
type SetTPMDevice tpmdetection.Type

// Apply implements `MeasureOption`
func (opt SetTPMDevice) Apply(config *MeasurementConfig) error {
	config.TPMDevice = tpmdetection.Type(opt)
	return nil
}
