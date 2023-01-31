package tpmconds

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type TPMIsInited struct{}

func (TPMIsInited) Check(s *types.State) bool {
	t, err := tpm.GetFrom(s)
	if err != nil {
		return false
	}

	return t.IsInitialized()
}
