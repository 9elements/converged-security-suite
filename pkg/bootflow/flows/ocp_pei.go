package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/commonconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/tpmconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
	"github.com/linuxboot/fiano/pkg/guid"
)

// OCPPEI represents the steps of the OCP (Open Compute Project) implementation
// of PEI (Pre-EFI Initialization of BIOS).
var OCPPEI = types.Flow{
	commonsteps.SetActor(actors.OCPPEI{}),
	commonsteps.If(commonconds.Not(tpmconds.TPMIsInited{}), tpmsteps.InitTPM(0)),
	tpmsteps.Measure(0, datasources.PCDVariable("FirmwareVendorVersion")),
	tpmsteps.Measure(0, datasources.UEFIGUIDFirst([]guid.GUID{ffsConsts.GUIDDXE, ffsConsts.GUIDDXEContainer})),
	tpmsteps.Measure(0, datasources.Bytes{0, 0, 0, 0}),
}
