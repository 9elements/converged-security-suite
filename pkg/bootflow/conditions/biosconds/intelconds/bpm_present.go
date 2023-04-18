package intelconds

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// BPMPresent checks if Intel Boot Policy Manifest is present.
type BPMPresent struct{}

var _ types.Condition = (*BPMPresent)(nil)

// Check implements types.Condition.
func (BPMPresent) Check(ctx context.Context, s *types.State) bool {
	accessor, err := intelbiosimage.Get(ctx, s)
	if err != nil {
		return false
	}

	bpm, _, _ := accessor.BootPolicyManifest()
	return bpm != nil
}
