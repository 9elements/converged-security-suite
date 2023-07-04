package validator

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// ValidatorActorsAreProtected validates if the code of an Actor is protected, before
// the Actor is executed.
type ValidatorActorsAreProtected struct{}

var _ Validator = (*ValidatorActorsAreProtected)(nil)

// Validate implements Validator.
func (ValidatorActorsAreProtected) Validate(_ context.Context, _ *types.State, l bootengine.Log) Issues {
	var result []Issue
	var measured types.References
	var prevActor types.Actor
	for stepIdx, step := range l {
		prevMeasured := measured
		newMeasuredRefs := step.MeasuredData.References()
		if err := newMeasuredRefs.Resolve(); err != nil {
			result = append(result, Issue{
				StepIdx: uint(stepIdx),
				StepIssue: bootengine.StepIssue{
					Coords: bootengine.StepIssueCoordsActor{},
					Issue:  fmt.Errorf("unable to resolve the measured references %s: %w", format.NiceString(measured), err),
				},
			})
		}
		measured = append(measured, newMeasuredRefs...)
		measured.SortAndMerge()
		if step.Actor == nil {
			continue
		}
		if step.Actor == prevActor {
			continue
		}
		prevActor = step.Actor
		if step.ActorCode == nil {
			continue
		}
		actorRefs := step.ActorCode.References.Exclude() // a copy
		if err := actorRefs.Resolve(); err != nil {
			result = append(result, Issue{
				StepIdx: uint(stepIdx),
				StepIssue: bootengine.StepIssue{
					Coords: bootengine.StepIssueCoordsActor{},
					Issue:  fmt.Errorf("unable to resolve the actor references %s: %w", format.NiceString(actorRefs), err),
				},
			})
		}
		nonMeasured := actorRefs.Exclude(prevMeasured...)
		if len(nonMeasured) == 0 {
			continue
		}

		if err := nonMeasured.Resolve(); err != nil {
			result = append(result, Issue{
				StepIdx: uint(stepIdx),
				StepIssue: bootengine.StepIssue{
					Coords: bootengine.StepIssueCoordsActor{},
					Issue:  fmt.Errorf("unable to resolve references %s: %w", format.NiceString(nonMeasured), err),
				},
			})
		}
		result = append(result, Issue{
			StepIdx: uint(stepIdx),
			StepIssue: bootengine.StepIssue{
				Coords: bootengine.StepIssueCoordsActor{},
				Issue: fmt.Errorf(
					"actor %s executed step %d, while their areas %s were not protected; protected by this moment were only: %v",
					format.NiceString(step.Actor),
					stepIdx,
					format.NiceString(nonMeasured),
					format.NiceString(measured),
				),
			},
		})
	}
	return result
}
