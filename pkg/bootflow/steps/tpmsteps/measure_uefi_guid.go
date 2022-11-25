package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/linuxboot/fiano/pkg/guid"
)

func MeasureUEFIGUIDFirst(pcrID pcrtypes.ID, orList ...guid.GUID) types.Step {
	return types.StaticStep{
		tpmactions.NewTPMEvent(pcrID, datasources.UEFIGUIDFirst(orList), nil),
	}
}