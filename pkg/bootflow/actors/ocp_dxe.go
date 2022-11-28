package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

// OCPDXE represents the OCP (Open Compute Project) implementation of DXE.
type OCPDXE struct{}

// ResponsibleCode implements types.Actor.
func (ocpDXE OCPDXE) ResponsibleCode() types.DataSource {
	return datasources.UEFIGUIDFirst{consts.GUIDDXE, consts.GUIDDXEContainer}
}
