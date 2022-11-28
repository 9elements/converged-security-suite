package tpmsteps

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/linuxboot/fiano/pkg/guid"
)

// MeasureUEFIGUIDFirst measures UEFI objects of the specified GUID. It tries
// to find the objects using specified GUIDs in the given order until
// the first non-empty or erroneous result.
func MeasureUEFIGUIDFirst(pcrID pcrtypes.ID, orList ...guid.GUID) types.Step {
	return types.StaticStep{
		tpmactions.NewTPMEvent(pcrID, datasources.UEFIGUIDFirst(orList), nil),
	}
}
