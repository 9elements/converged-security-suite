package intelconds

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type FITPresent struct{}

func (FITPresent) Check(s *types.State) bool {
	intelFW, err := intelbiosimage.Get(s)
	if err != nil {
		return false
	}

	fitEntries, _ := intelFW.FIT()
	return fitEntries != nil
}
