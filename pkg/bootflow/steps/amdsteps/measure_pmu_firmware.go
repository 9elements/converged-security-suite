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

type MeasurePMUFirmware struct{}

var _ types.Step = (*MeasurePMUFirmware)(nil)

func (MeasurePMUFirmware) Actions(ctx context.Context, s *types.State) types.Actions {
	var actions types.Actions

	actions = append(actions, measureToTPMEachRangeSeparately(ctx, s, pcr.ID(0), amddata.BIOSDirectoryEntries(amdbiosimage.DirectoryLevelAll, manifest.PMUFirmwareInstructionsEntry), tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB, "PMUDataInstructions")...)
	actions = append(actions, measureToTPMEachRangeSeparately(ctx, s, pcr.ID(0), amddata.BIOSDirectoryEntries(amdbiosimage.DirectoryLevelAll, manifest.PMUFirmwareDataEntry), tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB, "PMUFirmwareData")...)
	return actions
}
