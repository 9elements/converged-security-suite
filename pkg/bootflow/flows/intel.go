package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors/intelactors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/intelsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
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
	commonsteps.Panic("legacy TXT flow is not implemented"),
})
