package tpmactions

import (
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

func (init *TPMInit) Apply(state *types.State) error {
	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}
	return t.TPMInit(init.Locality, init)
}

func (init TPMInit) GoString() string {
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

func (init *TPMInitLazy) Apply(state *types.State) error {
	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}
	if t.IsInitialized() {
		return nil
	}
	return t.TPMInit(init.Locality, init)
}

func (init TPMInitLazy) GoString() string {
	return fmt.Sprintf("TPMInitLazy(%d)", init.Locality)
}
