package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors/intelactors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/intelsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

var Intel = types.NewFlow("Intel", types.Steps{
	commonsteps.If(intelconds.BPMPresent{}, commonsteps.SetFlow(IntelCBnT), nil),
	commonsteps.SetFlow(IntelLegacyTXT),
})

var IntelCBnT = types.NewFlow("IntelCBnT", types.Steps{
	commonsteps.SetActor(intelactors.PCH{}),
	intelsteps.VerifyACM(IntelCBnTFailure),
	intelsteps.VerifyKM(IntelCBnTFailure),
	intelsteps.VerifyBPM(IntelCBnTFailure),
	intelsteps.VerifyIBB(IntelCBnTFailure),
	commonsteps.SetActor(intelactors.ACM{}),
	tpmsteps.InitTPM(3, true),
	intelsteps.MeasurePCR0DATA{},
	commonsteps.SetFlow(PEI),
})

var IntelCBnTFailure = types.NewFlow("IntelCBnTFailure", types.Steps{
	commonsteps.SetFlow(PEI),
})

var IntelLegacyTXT = types.NewFlow("IntelLegacyTXT", types.Steps{
	intelsteps.VerifyACM(PEI),
	commonsteps.SetActor(intelactors.ACM{}),
	tpmsteps.InitTPM(3, true),
	intelsteps.MeasureACMDate{},
	intelsteps.MeasureFITData(fit.EntryTypeBIOSStartupModuleEntry),
	tpmsteps.Measure(0, tpmeventlog.EV_SEPARATOR, datasources.Bytes{0, 0, 0, 0}),
	commonsteps.SetFlow(PEI),
})
