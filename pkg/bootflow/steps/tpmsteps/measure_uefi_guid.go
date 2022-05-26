package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/guid"
)

func MeasureUEFIGUIDFirst(orList ...guid.GUID) types.Step {
	return types.StaticStep{
		tpmactions.NewTPMEvent(0, datasources.UEFIGUIDFirst(orList), nil),
	}
}
