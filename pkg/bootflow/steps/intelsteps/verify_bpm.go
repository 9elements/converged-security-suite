package intelsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/intelactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// VerifyBPMType is just the type implementing VerifyBPM.
type VerifyBPMType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyBPMType)(nil)

// VerifyBPM is a types.Step to verify if Intel Boot Policy Manifest
// is valid (and jump to another flow if it is not).
func VerifyBPM(fallbackFlow types.Flow) VerifyBPMType {
	return VerifyBPMType{
		FallbackFlow: fallbackFlow,
	}
}

// Actions implements types.Step.
func (v VerifyBPMType) Actions(ctx context.Context, s *types.State) types.Actions {
	if (intelconds.ValidBPM{}).Check(ctx, s) {
		return types.Actions{
			intelactions.SetPCHVerified(inteldata.FITFirst(fit.EntryTypeBootPolicyManifest)),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
