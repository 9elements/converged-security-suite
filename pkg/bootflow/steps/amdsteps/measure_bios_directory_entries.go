package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/amd/manifest"
)

type MeasureBIOSStaticEntries struct{}

var _ types.Step = (*MeasureBIOSStaticEntries)(nil)

var entryTypes = []manifest.BIOSDirectoryTableEntryType{
	manifest.BIOSRTMVolumeEntry,
	manifest.PMUFirmwareInstructionsEntry,
	manifest.PMUFirmwareDataEntry,
	manifest.MicrocodePatchEntry,
	manifest.APCBDataBackupEntry,
	manifest.VideoInterpreterEntry,
	manifest.BIOSDirectoryTableLevel2Entry,
}

func (MeasureBIOSStaticEntries) Actions(ctx context.Context, s *types.State) types.Actions {
	_ = entryTypes
	// TODO: verify through signatures
	//       amddata.BIOSDirectoryEntries(amdbiosimage.DirectoryLevelL1, entryTypes...)
	//       amddata.BIOSDirectoryEntries(amdbiosimage.DirectoryLevelL2, entryTypes...)
	return nil
}
