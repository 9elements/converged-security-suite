package intelsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/intelactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors/intelactors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// VerifyACMType is just the type implementing VerifyACM.
type VerifyACMType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyACMType)(nil)

// VerifyACM is a types.Step to verify if ACM is valid (and jump to another flow if it isn't).
func VerifyACM(fallbackFlow types.Flow) VerifyACMType {
	return VerifyACMType{
		FallbackFlow: fallbackFlow,
	}
}

// Actions implements types.Step.
func (v VerifyACMType) Actions(s *types.State) types.Actions {
	if (intelconds.ValidACM{}).Check(s) {
		return types.Actions{
			intelactions.SetPCHVerified(intelactors.ACM{}.ResponsibleCode()),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
