package validator

import (
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
func (ValidatorActorsAreProtected) Validate(l bootengine.Log) Issues {
	var result []Issue
	var measured types.References
	for stepIdx, step := range l {
		prevMeasured := measured
		measured = append(measured, step.MeasuredData.MeasuredReferences()...)
		if step.ActorCode == nil {
			continue
		}
		nonMeasured := step.ActorCode.References.Exclude(prevMeasured...)
		if len(nonMeasured) == 0 {
			continue
		}
		result = append(result, Issue{
			StepIdx: uint(stepIdx),
			StepIssue: bootengine.StepIssue{
				Coords: bootengine.StepIssueCoordsActor{},
				Issue: fmt.Errorf(
					"actor %s executed step %d, while their areas %s were not protected; protected: %v",
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
