package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// Measure just measures abstract data.
func Measure(pcrID pcr.ID, eventType tpmeventlog.EventType, data types.DataSource) types.Step {
	return types.StaticStep{
		tpmactions.NewTPMEvent(pcrID, data, eventType, nil),
	}
}
