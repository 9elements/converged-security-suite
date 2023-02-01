package tpmconds

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// TPMIsInited checks if Trusted Platform Module is initialized.
type TPMIsInited struct{}

// Check implements types.Condition.
func (TPMIsInited) Check(s *types.State) bool {
	t, err := tpm.GetFrom(s)
	if err != nil {
		return false
	}

	return t.IsInitialized()
}
