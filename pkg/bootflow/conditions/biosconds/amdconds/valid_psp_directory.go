package amdconds

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type ValidPSPDirectory struct{}

// Check implements types.Condition.
func (ValidPSPDirectory) Check(ctx context.Context, s *types.State) bool {
	// TODO: implement this
	return true
}
