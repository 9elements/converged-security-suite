package intelconds

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// BPMPresent checks if Intel Firmware Interface Table is present.
type FITPresent struct{}

// Check implements types.Condition.
func (FITPresent) Check(ctx context.Context, s *types.State) bool {
	intelFW, err := intelbiosimage.Get(ctx, s)
	if err != nil {
		return false
	}

	fitEntries, _ := intelFW.FIT()
	return fitEntries != nil
}
