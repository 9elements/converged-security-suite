package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
)

// MeasurePCDVariable measures a PCD variable of the specified name to the specified PCR.
func MeasurePCDVariable(pcrID pcrtypes.ID, name string) types.Step {
	return types.StaticStep{
		// not implemented, yet
	}
}
