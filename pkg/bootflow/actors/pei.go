package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// PEI represents Pre-EFI Initialization code.
type PEI struct{}

// ResponsibleCode implements types.Actor.
func (pei PEI) ResponsibleCode() types.DataSource {
	return datasources.UEFIFilesByType{
		uefi.FVFileTypeSECCore,
		uefi.FVFileTypePEICore,
		uefi.FVFileTypePEIM,
		uefi.FVFileTypeCombinedPEIMDriver,
		uefi.FVFileTypeSMM,
		uefi.FVFileTypeCombinedSMMDXE,
		uefi.FVFileTypeSMMCore,
		uefi.FVFileTypeSMMStandalone,
		uefi.FVFileTypeSMMCoreStandalone,
		uefi.FVFileTypeOEMMin,
		uefi.FVFileTypeOEMMax,
	}
}
