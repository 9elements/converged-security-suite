package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// DXE represents the steps of the DXE
var DXE = types.NewFlow("DXE", types.Steps{
	commonsteps.SetActor(actors.DXE{}),
})
