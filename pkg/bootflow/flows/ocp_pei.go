package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/amdconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/ocpconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/tpmconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
	"github.com/linuxboot/fiano/pkg/guid"
)

var (
	// I have no idea what there volumes are and why they are measured,
	// this was restored by just reading the output TPM EventLog.
	guidOCPV1Vol0Intel = *guid.MustParse("1638673D-EFE6-400B-951F-ABAC2CB31C60")
	guidOCPV1Vol1Intel = *guid.MustParse("14E428FA-1A12-4875-B637-8B3CC87FDF07")
	guidOCPV1Vol2Intel = *guid.MustParse("013B9639-D6D5-410F-B7A9-F9173C56ECDA")
)

var OCPPEI = types.NewFlow("OCPPEI", types.Steps{
	commonsteps.SetActor(actors.PEI{}),
	commonsteps.If(tpmconds.TPMIsInited{}, nil, tpmsteps.InitTPM(0, false)),
	tpmsteps.Measure(0, tpmeventlog.EV_S_CRTM_VERSION, datasources.PCDVariable("FirmwareVendorVersion")),
	commonsteps.If(
		ocpconds.IsOCPv1{},
		ocpV1Measurements,
		tpmsteps.Measure(0, tpmeventlog.EV_POST_CODE, datasources.UEFIGUIDFirst([]guid.GUID{ffsConsts.GUIDDXEContainer, ffsConsts.GUIDDXE})),
	),
	tpmsteps.Measure(0, tpmeventlog.EV_SEPARATOR, datasources.Bytes{0, 0, 0, 0}),
	commonsteps.SetFlow(DXE),
})

var ocpV1Measurements = commonsteps.If(
	amdconds.ManifestPresent{},
	commonsteps.MergeSteps(ocpV1MeasurementsAMD),
	commonsteps.MergeSteps(ocpV1MeasurementsIntel),
)

var ocpV1MeasurementsAMD = types.Steps{
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.MemRanges{{Offset: 0xFF7F1000 + 0x1034, Length: 0x20}}), // TODO: this was bruteforced on a specific firmware, replace with analytical way to find the ranges
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.MemRanges{{Offset: 0xFF7F1000 + 0x1074, Length: 0x20}}), // TODO: this was bruteforced on a specific firmware, replace with analytical way to find the ranges
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.MemRanges{{Offset: 0xFF7F1000 + 0x10B4, Length: 0x20}}), // TODO: this was bruteforced on a specific firmware, replace with analytical way to find the ranges
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.MemRanges{{Offset: 0xFF7F1000 + 0x11D4, Length: 0x20}}), // TODO: this was bruteforced on a specific firmware, replace with analytical way to find the ranges
}

var ocpV1MeasurementsIntel = types.Steps{
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.UEFIGUIDFirst([]guid.GUID{guidOCPV1Vol0Intel})),
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.UEFIGUIDFirst([]guid.GUID{guidOCPV1Vol1Intel})),
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.UEFIGUIDFirst([]guid.GUID{guidOCPV1Vol2Intel})),
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.UEFIGUIDFirst([]guid.GUID{ffsConsts.GUIDDXEContainer, ffsConsts.GUIDDXE})),
}
