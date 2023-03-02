package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors/intelactors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/intelsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

var Intel = types.Flow{
	commonsteps.If(intelconds.BPMPresent{}, commonsteps.SetFlow(IntelCBnT)),
	commonsteps.SetFlow(IntelLegacyTXT),
}

var IntelCBnT = types.Flow{
	commonsteps.SetActor(intelactors.PCH{}),
	intelsteps.VerifyACM(IntelCBnTFailure),
	intelsteps.VerifyKM(IntelCBnTFailure),
	intelsteps.VerifyBPM(IntelCBnTFailure),
	intelsteps.VerifyIBB(IntelCBnTFailure),
	commonsteps.SetActor(intelactors.ACM{}),
	tpmsteps.InitTPM(3),
	intelsteps.MeasurePCR0DATA{},
	commonsteps.SetFlow(PEI),
}

var IntelCBnTFailure = types.Flow{
	commonsteps.SetFlow(PEI),
}

var IntelLegacyTXT = types.Flow{
	commonsteps.Panic("legacy TXT flow is not implemented"),
}
