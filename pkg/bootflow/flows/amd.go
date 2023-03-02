package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

var AMD = types.Flow{
	commonsteps.SetFlow(PEI),
}
