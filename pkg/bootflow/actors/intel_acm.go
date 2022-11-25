package actors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

type IntelACM struct{}

func (intelACM IntelACM) ResponsibleCode() types.DataSource {
	return datasources.IntelFITFirst(fit.EntryTypeStartupACModuleEntry)
}
