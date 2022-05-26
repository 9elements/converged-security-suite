package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

func OCPDXE() types.Flow {
	return types.Flow{
		tpmsteps.MeasurePCDVariable(0, "FirmwareVendorVersion"),
		tpmsteps.MeasureUEFIGUIDFirst(0, ffsConsts.GUIDDXE, ffsConsts.GUIDDXEContainer),
		tpmsteps.MeasureSeparator(0),
	}
}
