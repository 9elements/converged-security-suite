package tpmactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// TPMInit forcefully inits TPM (returns an error, if TPM is already initialized).
type TPMInit struct {
	Locality uint8
}

var _ types.Action = (*TPMInit)(nil)

// NewTPMInit returns a new instance of TPMInit.
func NewTPMInit(
	locality uint8,
) *TPMInit {
	return &TPMInit{
		Locality: locality,
	}
}

// Apply implements types.Action.
func (init *TPMInit) Apply(ctx context.Context, state *types.State) error {
	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}
	return t.TPMInit(ctx, init.Locality, NewLogInfoProvider(state))
}

// String implements fmt.Stringer.
func (init TPMInit) String() string {
	return fmt.Sprintf("TPMInit(%d)", init.Locality)
}
