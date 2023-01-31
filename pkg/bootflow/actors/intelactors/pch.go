package intelactors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type PCH struct{}

var _ types.Actor = (*PCH)(nil)

// ResponsibleCode implements types.Actor.
func (PCH) ResponsibleCode() types.DataSource {
	return nil
}
