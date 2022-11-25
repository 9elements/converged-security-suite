package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

type OCPDXE struct{}

func (ocpDXE OCPDXE) ResponsibleCode() types.DataSource {
	return datasources.UEFIGUIDFirst{consts.GUIDDXE, consts.GUIDDXEContainer}
}
