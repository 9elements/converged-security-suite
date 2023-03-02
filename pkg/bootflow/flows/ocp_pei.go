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

var (
	// I have no idea what there volumes are and why they are measured,
	// this was restored by just reading the output TPM EventLog.
	guidOCPV1Vol0 = *guid.MustParse("1638673D-EFE6-400B-951F-ABAC2CB31C60")
	guidOCPV1Vol1 = *guid.MustParse("14E428FA-1A12-4875-B637-8B3CC87FDF07")
	guidOCPV1Vol2 = *guid.MustParse("013B9639-D6D5-410F-B7A9-F9173C56ECDA")
)

// OCPPEIv0 represents the steps of the OCP (Open Compute Project) implementation
// of PEI (Pre-EFI Initialization of BIOS) before ~2022.
var OCPPEIv0 = types.Flow{
	commonsteps.SetActor(actors.PEI{}),
	commonsteps.If(commonconds.Not(tpmconds.TPMIsInited{}), tpmsteps.InitTPM(0)),
	tpmsteps.Measure(0, datasources.PCDVariable("FirmwareVendorVersion")),
	tpmsteps.Measure(0, datasources.UEFIGUIDFirst([]guid.GUID{ffsConsts.GUIDDXE, ffsConsts.GUIDDXEContainer})),
	tpmsteps.Measure(0, datasources.Bytes{0, 0, 0, 0}),
	commonsteps.SetFlow(DXE),
}

// OCPPEIv1 represents the steps of the OCP (Open Compute Project) implementation
// of PEI (Pre-EFI Initialization of BIOS) after ~2022.
var OCPPEIv1 = types.Flow{
	commonsteps.SetActor(actors.PEI{}),
	commonsteps.If(commonconds.Not(tpmconds.TPMIsInited{}), tpmsteps.InitTPM(0)),
	tpmsteps.Measure(0, datasources.PCDVariable("FirmwareVendorVersion")),
	tpmsteps.Measure(0, datasources.UEFIGUIDFirst([]guid.GUID{guidOCPV1Vol0})),
	tpmsteps.Measure(0, datasources.UEFIGUIDFirst([]guid.GUID{guidOCPV1Vol1})),
	tpmsteps.Measure(0, datasources.UEFIGUIDFirst([]guid.GUID{guidOCPV1Vol2})),
	tpmsteps.Measure(0, datasources.UEFIGUIDFirst([]guid.GUID{ffsConsts.GUIDDXE, ffsConsts.GUIDDXEContainer})),
	tpmsteps.Measure(0, datasources.Bytes{0, 0, 0, 0}),
	commonsteps.SetFlow(DXE),
}
