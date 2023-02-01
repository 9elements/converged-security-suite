package commonconds

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type not struct {
	types.Condition
}

// Not negates the given condition.
func Not(cond types.Condition) not {
	return not{Condition: cond}
}

// Check implements types.Condition.
func (not not) Check(ctx context.Context, s *types.State) bool {
	return !not.Condition.Check(ctx, s)
}

// String implements fmt.Stringer.
func (not not) String() string {
	return fmt.Sprintf("!%s", format.NiceString(not.Condition))
}
