package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors/intelactors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/commonconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/ocpconds"
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
	commonsteps.If(commonconds.Not(intelconds.ValidACM{}), commonsteps.SetFlow(IntelCBnTFailure)),
	commonsteps.If(commonconds.Not(intelconds.ValidKM{}), commonsteps.SetFlow(IntelCBnTFailure)),
	commonsteps.If(commonconds.Not(intelconds.ValidBPM{}), commonsteps.SetFlow(IntelCBnTFailure)),
	commonsteps.If(commonconds.Not(intelconds.ValidIBB{}), commonsteps.SetFlow(IntelCBnTFailure)),
	commonsteps.SetActor(intelactors.ACM{}),
	tpmsteps.InitTPM(3),
	intelsteps.MeasurePCR0DATA{},
	commonsteps.SetFlow(IntelResetVector),
}

var IntelCBnTFailure = types.Flow{
	commonsteps.SetFlow(IntelResetVector),
}

var IntelResetVector = types.Flow{
	commonsteps.SetActor(actors.Unknown{}),
	commonsteps.If(ocpconds.IsOCPv0{}, commonsteps.SetFlow(OCPPEIv0)),
	commonsteps.If(ocpconds.IsOCPv1{}, commonsteps.SetFlow(OCPPEIv1)),
	commonsteps.Panic("unknown flow: is not OCP"),
}

var IntelLegacyTXT = types.Flow{
	commonsteps.Panic("legacy TXT flow is not implemented"),
}
