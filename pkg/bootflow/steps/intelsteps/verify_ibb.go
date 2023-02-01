package intelsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/intelactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// VerifyIBBType is just the type implementing VerifyIBB.
type VerifyIBBType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyKMType)(nil)

// VerifyBPM is a types.Step to verify if Initial Boot Block
// is valid (and jump to another flow if it is not).
func VerifyIBB(fallbackFlow types.Flow) VerifyIBBType {
	return VerifyIBBType{
		FallbackFlow: fallbackFlow,
	}
}

// Actions implements types.Step.
func (v VerifyIBBType) Actions(ctx context.Context, s *types.State) types.Actions {
	if (intelconds.ValidIBB{}).Check(ctx, s) {
		return types.Actions{
			intelactions.SetPCHVerified(inteldata.IBB{}),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
