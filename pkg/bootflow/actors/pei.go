package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// PEI represents Pre-EFI Initialization code.
type PEI struct{}

// ResponsibleCode implements types.Actor.
func (PEI) ResponsibleCode() types.DataSource {
	return datasources.SortAndMerge(datasources.Concat{
		datasources.UEFIFilesByType{
			uefi.FVFileTypePEICore,
			uefi.FVFileTypePEIM,
			uefi.FVFileTypeCombinedPEIMDriver,
		},
		datasources.VolumeOf(datasources.UEFIFilesByName{"PeiCore"}),
	})
}
