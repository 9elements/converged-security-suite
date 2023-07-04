package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/uefi"
)

type DXE struct{}

// ResponsibleCode implements types.Actor.
func (DXE) ResponsibleCode() types.DataSource {
	return datasources.SortAndMerge(datasources.Concat{
		datasources.UEFIFilesByType{
			uefi.FVFileTypeDXECore,
			uefi.FVFileTypeDriver,
			uefi.FVFileTypeApplication,
			uefi.FVFileTypeCombinedSMMDXE,
			uefi.FVFileTypeSMMCore,
			uefi.FVFileTypeSMMStandalone,
			uefi.FVFileTypeSMMCoreStandalone,
		},
		datasources.VolumeOf(datasources.UEFIFilesByName{"DxeCore"}),
	})
}
