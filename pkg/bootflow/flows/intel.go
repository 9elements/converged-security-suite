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

var Intel = NewFlow("Intel", types.Steps{
	commonsteps.If(intelconds.BPMPresent{}, commonsteps.SetFlow(IntelCBnT), nil),
	commonsteps.SetFlow(IntelLegacyTXTEnabled),
})

var IntelCBnT = NewFlow("IntelCBnT", types.Steps{
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

var IntelCBnTFailure = NewFlow("IntelCBnTFailure", types.Steps{
	commonsteps.SetFlow(IntelLegacyTXTDisabled),
})

var IntelLegacyTXTEnabled = NewFlow("IntelLegacyTXTEnabled", types.Steps{
	commonsteps.SetActor(intelactors.PCH{}),
	intelsteps.VerifyACM(IntelLegacyTXTDisabled),
	commonsteps.SetActor(intelactors.ACM{}),
	tpmsteps.InitTPM(3, true),
	intelsteps.MeasureACMDate{},
	intelsteps.MeasureFITData(fit.EntryTypeBIOSStartupModuleEntry),
	tpmsteps.Measure(0, tpmeventlog.EV_SEPARATOR, datasources.Bytes{0, 0, 0, 0}),
	commonsteps.SetFlow(PEI),
})

var IntelLegacyTXTEnabledTPM12 = NewFlow("IntelLegacyTXTEnabledTPM12", types.Steps{
	commonsteps.Panic("legacy TXT flow for TPM1.2 is not implemented"),
})

var IntelLegacyTXTDisabled = NewFlow("IntelLegacyTXTDisabled", types.Steps{
	commonsteps.SetFlow(PEI),
})
