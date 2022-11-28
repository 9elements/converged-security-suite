package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

// OCPPEI represents the steps of the OCP (Open Compute Project) implementation
// of PEI (Pre-EFI Initialization of BIOS).
func OCPPEI() types.Flow {
	return types.Flow{
		commonsteps.SetActor(actors.OCPPEI{}),
		tpmsteps.InitTPMLazy(0),
		tpmsteps.MeasurePCDVariable(0, "FirmwareVendorVersion"),
		tpmsteps.MeasureUEFIGUIDFirst(0, ffsConsts.GUIDDXE, ffsConsts.GUIDDXEContainer),
		tpmsteps.MeasureSeparator(0),
	}
}
