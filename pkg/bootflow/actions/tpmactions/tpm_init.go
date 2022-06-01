package tpmactions

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type TPMInit struct {
	Locality uint8
}

func NewTPMInit(locality uint8) TPMInit {
	return TPMInit{
		Locality: locality,
	}
}

func (init TPMInit) Apply(state *types.State) error {
	return tpm.StateExec(state, func(t *tpm.TPM) error {
		if t.IsInitialized() {
			return nil
		}
		return t.TPMInit(init.Locality)
	})
}

func (init TPMInit) GoString() string {
	return fmt.Sprintf("TPMInit(%d)", init.Locality)
}

type TPMInitLazy struct {
	TPMInit
}

func NewTPMInitLazy(locality uint8) TPMInitLazy {
	return TPMInitLazy{TPMInit: NewTPMInit(locality)}
}

func (init TPMInitLazy) Apply(state *types.State) error {
	return tpm.StateExec(state, func(t *tpm.TPM) error {
		if t.IsInitialized() {
			return nil
		}
		return init.TPMInit.Apply(state)
	})
}

func (init TPMInitLazy) GoString() string {
	return fmt.Sprintf("TPMInitLazy(%d)", init.Locality)
}
