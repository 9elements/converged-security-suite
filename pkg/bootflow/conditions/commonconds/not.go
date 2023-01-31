package commonconds

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type not struct {
	types.Condition
}

func Not(cond types.Condition) types.Condition {
	return not{Condition: cond}
}

func (not not) Check(s *types.State) bool {
	return !not.Condition.Check(s)
}

func (not not) String() string {
	return fmt.Sprintf("!%s", format.NiceString(not.Condition))
}
