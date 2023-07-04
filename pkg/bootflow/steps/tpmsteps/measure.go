package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// Measure just measures abstract data.
func Measure(pcrID pcrtypes.ID, eventType tpmeventlog.EventType, data types.DataSource) types.Step {
	return types.StaticStep{
		tpmactions.NewTPMEvent(0, data, eventType, nil),
	}
}
