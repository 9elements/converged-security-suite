package intelsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/intelactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

type VerifyKMType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyKMType)(nil)

func VerifyKM(fallbackFlow types.Flow) VerifyKMType {
	return VerifyKMType{
		FallbackFlow: fallbackFlow,
	}
}

func (v VerifyKMType) Actions(s *types.State) types.Actions {
	if (intelconds.ValidKM{}).Check(s) {
		return types.Actions{
			intelactions.SetPCHVerified(inteldata.FITFirst(fit.EntryTypeKeyManifestRecord)),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
