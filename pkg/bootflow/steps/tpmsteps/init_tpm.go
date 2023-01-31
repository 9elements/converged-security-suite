package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// InitTPM initializes the TPM.
func InitTPM(locality uint8) types.Step {
	return types.StaticStep{
		tpmactions.NewTPMInit(locality),
	}
}
