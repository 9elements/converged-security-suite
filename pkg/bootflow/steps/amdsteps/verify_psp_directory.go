package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/amdactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/amdconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// VerifyPSPDirectoryType is just the type implementing VerifyPSPDirectory.
type VerifyPSPDirectoryType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyBIOSDirectoryType)(nil)

// VerifyPSPDirectory is a types.Step to verify if Intel Authenticated Code Module
// is valid (and jump to another flow if it is not).
func VerifyPSPDirectory(fallbackFlow types.Flow) VerifyPSPDirectoryType {
	return VerifyPSPDirectoryType{
		FallbackFlow: fallbackFlow,
	}
}

// Actions implements types.Step.
func (v VerifyPSPDirectoryType) Actions(ctx context.Context, s *types.State) types.Actions {
	if (amdconds.ValidPSPDirectory{}).Check(ctx, s) {
		return types.Actions{
			amdactions.SetPSPVerified(amddata.PSPDirectory{}),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
