package tpmactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type TPMInit struct {
	Locality uint8
}

func NewTPMInit(
	locality uint8,
) *TPMInit {
	return &TPMInit{
		Locality: locality,
	}
}

func (init *TPMInit) Apply(ctx context.Context, state *types.State) error {
	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}
	return t.TPMInit(ctx, init.Locality, NewLogInfoProvider(state))
}

func (init TPMInit) String() string {
	return fmt.Sprintf("TPMInit(%d)", init.Locality)
}

type TPMInitLazy struct {
	Locality uint8
}

func NewTPMInitLazy(
	locality uint8,
) *TPMInitLazy {
	return &TPMInitLazy{Locality: locality}
}

func (init *TPMInitLazy) Apply(ctx context.Context, state *types.State) error {
	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}
	if t.IsInitialized() {
		return nil
	}
	return t.TPMInit(ctx, init.Locality, NewLogInfoProvider(state))
}

func (init TPMInitLazy) String() string {
	return fmt.Sprintf("TPMInitLazy(%d)", init.Locality)
}
