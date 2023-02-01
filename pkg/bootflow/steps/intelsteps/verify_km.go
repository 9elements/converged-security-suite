package intelsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/intelactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// VerifyKMType is just the type implementing VerifyKM.
type VerifyKMType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyKMType)(nil)

// VerifyKM is a types.Step to verify if Intel Key Manifest
// is valid (and jump to another flow if it is not).
func VerifyKM(fallbackFlow types.Flow) VerifyKMType {
	return VerifyKMType{
		FallbackFlow: fallbackFlow,
	}
}

// Actions implements types.Step.
func (v VerifyKMType) Actions(ctx context.Context, s *types.State) types.Actions {
	if (intelconds.ValidKM{}).Check(ctx, s) {
		return types.Actions{
			intelactions.SetPCHVerified(inteldata.FITFirst(fit.EntryTypeKeyManifestRecord)),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
