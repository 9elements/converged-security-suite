package intelsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/intelactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

type VerifyBPMType struct {
	FallbackFlow types.Flow
}

var _ types.Step = (*VerifyBPMType)(nil)

func VerifyBPM(fallbackFlow types.Flow) VerifyBPMType {
	return VerifyBPMType{
		FallbackFlow: fallbackFlow,
	}
}

func (v VerifyBPMType) Actions(s *types.State) types.Actions {
	if (intelconds.ValidBPM{}).Check(s) {
		return types.Actions{
			intelactions.SetPCHVerified(inteldata.FITFirst(fit.EntryTypeBootPolicyManifest)),
		}
	}

	return types.Actions{
		commonactions.SetFlow(v.FallbackFlow),
	}
}
