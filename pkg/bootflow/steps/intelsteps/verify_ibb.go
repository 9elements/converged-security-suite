package intelsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/intelactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type VerifyIBBType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyKMType)(nil)

func VerifyIBB(fallbackFlow types.Flow) VerifyIBBType {
	return VerifyIBBType{
		FallbackFlow: fallbackFlow,
	}
}

func (v VerifyIBBType) Actions(s *types.State) types.Actions {
	if (intelconds.ValidIBB{}).Check(s) {
		return types.Actions{
			intelactions.SetPCHVerified(inteldata.IBB{}),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
