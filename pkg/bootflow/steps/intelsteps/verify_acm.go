package intelsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/intelactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors/intelactors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type VerifyACMType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyACMType)(nil)

func VerifyACM(fallbackFlow types.Flow) VerifyACMType {
	return VerifyACMType{
		FallbackFlow: fallbackFlow,
	}
}

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
