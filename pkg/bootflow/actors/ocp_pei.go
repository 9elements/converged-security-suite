package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

// OCPDXE represents the OCP (Open Compute Project) implementation of PEI.
type OCPPEI struct{}

// ResponsibleCode implements types.Actor.
func (ocpPEI OCPPEI) ResponsibleCode() types.DataSource {
	return datasources.UEFIGUIDFirst{consts.GUIDOCPPEI}
}
