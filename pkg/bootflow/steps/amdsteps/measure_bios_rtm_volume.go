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

type MeasureBIOSRTMVolume struct{}

var _ types.Step = (*MeasureBIOSRTMVolume)(nil)

func (MeasureBIOSRTMVolume) Actions(ctx context.Context, s *types.State) types.Actions {
	return measureToTPMEachRangeSeparately(ctx, s, pcr.ID(0), amddata.BIOSDirectoryEntries(amdbiosimage.DirectoryLevelAll, manifest.BIOSRTMVolumeEntry), tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB, "BIOSRTMVolume")
}
