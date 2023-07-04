package commonsteps

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type ifStep struct {
	Condition types.Condition
	ThenStep  types.Step
	ElseStep  types.Step
}

// If is a `types.Step` which returns Actions of `thenStep` if `condition` is satisfied,
// or Actions of `elseStep` otherwise.
func If(condition types.Condition, thenStep types.Step, elseStep types.Step) types.Step {
	return &ifStep{
		Condition: condition,
		ThenStep:  thenStep,
		ElseStep:  elseStep,
	}
}

// Actions implements types.Step.
func (step *ifStep) Actions(ctx context.Context, s *types.State) types.Actions {
	if step.Condition.Check(ctx, s) {
		if step.ThenStep == nil {
			return nil
		}
		return step.ThenStep.Actions(ctx, s)
	}

	if step.ElseStep == nil {
		return nil
	}
	return step.ElseStep.Actions(ctx, s)
}

// String implements fmt.Stringer.
func (step *ifStep) String() string {
	switch {
	case step.ThenStep != nil && step.ElseStep != nil:
		return fmt.Sprintf("if %v then %v else %v", format.NiceString(step.Condition), format.NiceString(step.ThenStep), format.NiceString(step.ElseStep))
	case step.ThenStep != nil:
		return fmt.Sprintf("if %v then %v", format.NiceString(step.Condition), format.NiceString(step.ThenStep))
	case step.ElseStep != nil:
		return fmt.Sprintf("unless %v do %v", format.NiceString(step.Condition), format.NiceString(step.ElseStep))
	default:
		return fmt.Sprintf("if %v then NOOP", format.NiceString(step.Condition))
	}
}
