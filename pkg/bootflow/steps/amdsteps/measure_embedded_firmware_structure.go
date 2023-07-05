package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

type MeasureEmbeddedFirmwareStructure struct{}

var _ types.Step = (*MeasureEmbeddedFirmwareStructure)(nil)

func (MeasureEmbeddedFirmwareStructure) Actions(ctx context.Context, s *types.State) types.Actions {
	return types.Actions{
		tpmactions.NewTPMEvent(pcr.ID(0), amddata.EmbeddedFirmware{}, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB, []byte("EmbeddedFirmware")),
	}
}
