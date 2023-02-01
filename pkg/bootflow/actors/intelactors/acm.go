package intelactors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/inteldata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// ACM is Intel Authenticated Code Module.
// It could be used to verify/measure IBB (Initial Boot Block), which
// in some flows includes PEI.
type ACM struct{}

var _ types.Actor = (*ACM)(nil)

// ResponsibleCode implements types.Actor.
func (ACM) ResponsibleCode() types.DataSource {
	return inteldata.FITFirst(fit.EntryTypeStartupACModuleEntry)
}
