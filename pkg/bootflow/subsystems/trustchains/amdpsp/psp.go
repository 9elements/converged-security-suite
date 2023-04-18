package amdpsp

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

var _ types.SubSystem = (*PSP)(nil)

// PSP is the AMD Platform Security Processor.
type PSP struct{}

// NewTPM returns a new instance of TPM.
func NewPSP() *PSP {
	return &PSP{}
}

// GetFrom returns a TPM given a State.
func GetFrom(state *types.State) (*PSP, error) {
	return types.GetSubSystemByTypeFromState[*PSP](state)
}

// IsInitialized returns if CommandInit was ever executed.
func (*PSP) IsInitialized() bool {
	return true
}
