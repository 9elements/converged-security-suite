package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/amdbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/linuxboot/fiano/pkg/amd/manifest"
)

type MeasurePMUFirmware struct{}

var _ types.Step = (*MeasurePMUFirmware)(nil)

func (MeasurePMUFirmware) Actions(ctx context.Context, s *types.State) types.Actions {
	var actions types.Actions

	actions = append(actions, measureToTPMEachRangeSeparately(ctx, s, pcrtypes.ID(0), amddata.BIOSDirectoryEntries(amdbiosimage.DirectoryLevelAll, manifest.PMUFirmwareInstructionsEntry), "PMUDataInstructions")...)
	actions = append(actions, measureToTPMEachRangeSeparately(ctx, s, pcrtypes.ID(0), amddata.BIOSDirectoryEntries(amdbiosimage.DirectoryLevelAll, manifest.PMUFirmwareDataEntry), "PMUFirmwareData")...)
	return actions
}
