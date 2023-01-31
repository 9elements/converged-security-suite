package intelconds

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type ValidACM struct{}

func (ValidACM) Check(s *types.State) bool {
	intelFW, err := intelbiosimage.Get(s)
	if err != nil {
		return false
	}

	acmData, acmEntry, err := intelFW.ACM()
	if err != nil {
		return false
	}

	// TODO: add checks here
	_, _ = acmData, acmEntry

	return true
}
