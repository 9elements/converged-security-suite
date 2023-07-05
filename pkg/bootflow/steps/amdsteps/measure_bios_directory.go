package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

type MeasureBIOSDirectory struct{}

var _ types.Step = (*MeasureBIOSDirectory)(nil)

func (MeasureBIOSDirectory) Actions(ctx context.Context, s *types.State) types.Actions {
	return measureToTPMEachRangeSeparately(ctx, s, pcr.ID(0), amddata.BIOSDirectory{}, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB, "BIOSDirectory")
}
