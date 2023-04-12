package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/ocpconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

var PEI = types.NewFlow("PEI", types.Steps{
	commonsteps.SetActor(actors.Unknown{}),
	commonsteps.If(ocpconds.IsOCPv0{}, commonsteps.SetFlow(OCPPEIv0)),
	commonsteps.If(ocpconds.IsOCPv1{}, commonsteps.SetFlow(OCPPEIv1)),
	commonsteps.Panic("unknown flow: is not OCP"),
})
