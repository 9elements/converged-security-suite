package intelsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

type MeasureFITData fit.EntryType

var _ types.Step = (*MeasureACMDate)(nil)

func (et MeasureFITData) Actions(ctx context.Context, state *types.State) types.Actions {
	return types.Actions{
		tpmactions.NewTPMEvent(
			pcrtypes.ID(0),
			inteldata.FITAll(fit.EntryType(et)),
			tpmeventlog.EV_S_CRTM_CONTENTS,
			[]byte("BIOS_startup_module"),
		),
	}
}
