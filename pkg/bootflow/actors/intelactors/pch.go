package intelactors

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// PCH is the Intel Platform Controller Hub.
//
// Actually, it is unclear if some actions are performed with builtin ucode or with PCH,
// but for now a good enough approximation.
type PCH struct{}

var _ types.Actor = (*PCH)(nil)

// ResponsibleCode implements types.Actor.
func (PCH) ResponsibleCode() types.DataSource {
	return nil
}
