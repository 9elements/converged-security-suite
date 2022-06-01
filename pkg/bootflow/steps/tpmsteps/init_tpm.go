package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

func InitTPMLazy(locality uint8) types.Step {
	return types.StaticStep{
		tpmactions.NewTPMInitLazy(locality),
	}
}
