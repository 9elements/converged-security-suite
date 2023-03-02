package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/amdactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/amdconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// VerifyBIOSDirectoryType is just the type implementing VerifyBIOSDirectory.
type VerifyBIOSDirectoryType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyBIOSDirectoryType)(nil)

// VerifyBIOSDirectory is a types.Step to verify if Intel Authenticated Code Module
// is valid (and jump to another flow if it is not).
func VerifyBIOSDirectory(fallbackFlow types.Flow) VerifyBIOSDirectoryType {
	return VerifyBIOSDirectoryType{
		FallbackFlow: fallbackFlow,
	}
}

// Actions implements types.Step.
func (v VerifyBIOSDirectoryType) Actions(ctx context.Context, s *types.State) types.Actions {
	if (amdconds.ValidBIOSDirectory{}).Check(ctx, s) {
		return types.Actions{
			amdactions.SetPSPVerified(amddata.BIOSDirectory{}),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
