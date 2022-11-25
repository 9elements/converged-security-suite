package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

func OCPDXE() types.Flow {
	return types.Flow{
		commonsteps.SetActorPredefined(actors.OCPPEI{}),
		tpmsteps.InitTPMLazy(0),
		tpmsteps.MeasurePCDVariable(0, "FirmwareVendorVersion"),
		tpmsteps.MeasureUEFIGUIDFirst(0, ffsConsts.GUIDDXE, ffsConsts.GUIDDXEContainer),
		commonsteps.SetActorPredefined(actors.OCPDXE{}),
		tpmsteps.MeasureSeparator(0),
	}
}
