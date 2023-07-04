package intelpch

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

var _ types.SubSystem = (*PCH)(nil)

// PCH is the Intel Platform Controller Hub.
type PCH struct{}

// NewTPM returns a new instance of TPM.
func NewPCH() *PCH {
	return &PCH{}
}

// GetFrom returns a TPM given a State.
func GetFrom(state *types.State) (*PCH, error) {
	return types.GetSubSystemByTypeFromState[*PCH](state)
}

// IsInitialized returns if CommandInit was ever executed.
func (PCH *PCH) IsInitialized() bool {
	return true
}
