package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
)

func MeasureSeparator(pcrID pcrtypes.ID) types.Step {
	return types.StaticStep{
		tpmactions.NewTPMEvent(0, datasources.StaticData{0, 0, 0, 0}, nil),
	}
}
