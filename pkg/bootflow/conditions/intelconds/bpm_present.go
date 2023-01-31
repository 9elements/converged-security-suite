package intelconds

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type BPMPresent struct{}

func (BPMPresent) Check(s *types.State) bool {
	accessor, err := intelbiosimage.Get(s)
	if err != nil {
		return false
	}

	bpm, _, _ := accessor.BootPolicyManifest()
	return bpm != nil
}
