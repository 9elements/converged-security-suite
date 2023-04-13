package commonsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// MergeSteps merges actions of multiple steps into one Step.
type MergeSteps types.Steps

var _ types.Step = (MergeSteps)(nil)

// Actions implements types.Step.
func (s MergeSteps) Actions(ctx context.Context, state *types.State) types.Actions {
	var result types.Actions
	for _, step := range s {
		result = append(result, step.Actions(ctx, state)...)
	}
	return result
}
