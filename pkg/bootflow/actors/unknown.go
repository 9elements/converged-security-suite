package actors

import "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"

// Unknown is a placeholder actor for cases where there is no knowledge
// about the actor.
type Unknown struct{}

// ResponsibleCode implements types.Actor.
func (Unknown) ResponsibleCode() types.DataSource {
	return nil
}
