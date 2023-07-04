package tpmsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// InitTPMStruct is the structured returned by InitTPM.
type InitTPMStruct struct {
	Locality uint8
	WithLog  bool
}

var _ types.Step = (*InitTPMStruct)(nil)

// Actions implements types.Step.
func (s InitTPMStruct) Actions(ctx context.Context, state *types.State) types.Actions {
	result := types.Actions{
		tpmactions.NewTPMInit(s.Locality),
	}
	if s.WithLog {
		result = append(result, LogInit(s.Locality).Actions(ctx, state)...)
	}
	return result
}

// InitTPM initializes the TPM.
func InitTPM(locality uint8, withLog bool) types.Step {
	return &InitTPMStruct{
		Locality: locality,
		WithLog:  withLog,
	}
}
