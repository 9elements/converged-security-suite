package actors

import "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"

type Unknown struct{}

// ResponsibleCode implements types.Actor.
func (Unknown) ResponsibleCode() types.DataSource {
	return nil
}
