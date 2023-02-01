package validator

import (
	"fmt"

	recursivesort "github.com/romnn/go-recursive-sort"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
)

// Issue is a single problem reported by a Validator.
type Issue struct {
	StepIdx uint
	bootengine.StepIssue
}

// String implements fmt.Stringer.
func (issue Issue) String() string {
	return fmt.Sprintf("step#%d %s", issue.StepIdx, issue.StepIssue)
}

// Issues is a slice of Issue-s.
type Issues []Issue

// Validator is an abstract validator, which checks if there are any problems
// in a boot process (using its log after the boot process finished).
type Validator interface {
	Validate(bootengine.Log) Issues
}

// Validators is a slice of Validator-s
type Validators []Validator

var _ Validator = Validators(nil)

// Validate implements Validator.
func (s Validators) Validate(l bootengine.Log) Issues {
	var result Issues
	for _, v := range s {
		result = append(result, v.Validate(l)...)
	}
	recursivesort.Sort(&result)
	return result
}

// All returns a copy to all known Validator-s.
func All() Validators {
	return Validators{
		ValidatorActorsAreProtected{},
		ValidatorFinalCoverageIsComplete{},
		ValidatorNoIssues{},
	}
}
