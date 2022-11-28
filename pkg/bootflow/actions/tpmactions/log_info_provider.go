package tpmactions

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// LogInfoProvider provides additional information used for tpm.CommandLog.
type LogInfoProvider types.State

// NewLogInfoProvider returns a new instance of LogInfoProvider.
func NewLogInfoProvider(s *types.State) *LogInfoProvider {
	return (*LogInfoProvider)(s)
}

// CauseCoordinates returns the coordinates of the Action, which
// is the reason, why the tpm.Command was executed.
func (p *LogInfoProvider) CauseCoordinates() tpm.CauseCoordinates {
	return (*types.State)(p).GetCurrentActionCoordinates()
}
