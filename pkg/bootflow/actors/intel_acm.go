package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// IntelACM is Intel Authenticated Code Module.
// It could be used to verify/measure IBB (Initial Boot Block), which
// in some flows includes PEI.
type IntelACM struct{}

var _ types.Actor = (*IntelACM)(nil)

// ResponsibleCode implements types.Actor.
func (intelACM *IntelACM) ResponsibleCode() types.DataSource {
	return datasources.IntelFITFirst(fit.EntryTypeStartupACModuleEntry)
}
