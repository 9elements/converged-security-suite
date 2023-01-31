package commonsteps

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type ifStep struct {
	Condition types.Condition
	ThenStep  types.Step
}

func If(condition types.Condition, thenStep types.Step) types.Step {
	return &ifStep{
		Condition: condition,
		ThenStep:  thenStep,
	}
}

func (step *ifStep) Actions(s *types.State) types.Actions {
	if step.Condition.Check(s) {
		return step.ThenStep.Actions(s)
	}
	return nil
}

func (step *ifStep) String() string {
	return fmt.Sprintf("if %v then %v", format.NiceString(step.Condition), format.NiceString(step.ThenStep))
}
