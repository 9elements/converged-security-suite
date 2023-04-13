package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/amdconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

var Root = types.NewFlow("Root", types.Steps{
	commonsteps.If(intelconds.FITPresent{}, commonsteps.SetFlow(Intel), nil),
	commonsteps.If(amdconds.ManifestPresent{}, commonsteps.SetFlow(AMD), nil),
	commonsteps.Panic("unknown flow: neither AMD not Intel"),
})
