package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
)

type OCPPEI struct{}

func (ocpPEI OCPPEI) ResponsibleCode() types.DataSource {
	return datasources.UEFIGUIDFirst{consts.GUIDOCPPEI}
}
