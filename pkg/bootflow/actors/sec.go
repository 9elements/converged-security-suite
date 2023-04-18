package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// SEC represents the SEC module of a BIOS region.
type SEC struct{}

// ResponsibleCode implements types.Actor.
func (SEC) ResponsibleCode() types.DataSource {
	return datasources.SortAndMerge(datasources.Concat{
		datasources.UEFIFilesByType{
			uefi.FVFileTypeSECCore,
		},
		datasources.VolumeOf(datasources.UEFIFilesByName{"SecCore"}),
	})
}
