package intelconds

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// ValidACM checks if the Intel Authenticated Code Module is valid (including its signatures).
type ValidACM struct{}

// Check implements types.Condition.
func (ValidACM) Check(ctx context.Context, s *types.State) bool {
	intelFW, err := intelbiosimage.Get(ctx, s)
	if err != nil {
		return false
	}

	acmData, acmEntry, err := intelFW.ACM()
	if err != nil {
		return false
	}

	// TODO: add checks here
	_, _ = acmData, acmEntry

	return true
}
