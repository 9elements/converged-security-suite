package amdactors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// PSP is the AMD Platform Secure Processor.
type PSP struct{}

var _ types.Actor = (*PSP)(nil)

// ResponsibleCode implements types.Actor.
func (PSP) ResponsibleCode() types.DataSource {
	return nil
}
