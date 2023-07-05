package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/amdbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/linuxboot/fiano/pkg/amd/manifest"
)

type MeasureMicrocodePatch struct{}

var _ types.Step = (*MeasureMicrocodePatch)(nil)

func (MeasureMicrocodePatch) Actions(ctx context.Context, s *types.State) types.Actions {
	return measureToTPMEachRangeSeparately(ctx, s, pcr.ID(0), amddata.BIOSDirectoryEntries(amdbiosimage.DirectoryLevelAll, manifest.MicrocodePatchEntry), tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB, "MicrocodePatch")
}
