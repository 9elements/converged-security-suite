package tpmactions

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type LogInfoProvider types.State

func NewLogInfoProvider(s *types.State) *LogInfoProvider {
	return (*LogInfoProvider)(s)
}

func (p *LogInfoProvider) CauseCoordinates() tpm.CauseCoordinates {
	return (*types.State)(p).GetCurrentActionCoordinates()
}
