package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

type MeasurePSPVersion struct{}

var _ types.Step = (*MeasurePSPVersion)(nil)

func (MeasurePSPVersion) Actions(ctx context.Context, s *types.State) types.Actions {
	return types.Actions{
		tpmactions.NewTPMEvent(pcr.ID(0), &amddata.PSPVersion{}, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB, []byte("PSP Version")),
	}
}
