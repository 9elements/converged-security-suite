package validator

import (
	"fmt"

	recursivesort "github.com/romnn/go-recursive-sort"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
)

type Issue struct {
	StepIdx uint
	bootengine.StepIssue
}

func (issue Issue) String() string {
	return fmt.Sprintf("step#%d %s", issue.StepIdx, issue.StepIssue)
}

type Issues []Issue

type Validator interface {
	Validate(bootengine.Log) Issues
}

type Validators []Validator

var _ Validator = Validators(nil)

func (s Validators) Validate(l bootengine.Log) Issues {
	var result Issues
	for _, v := range s {
		result = append(result, v.Validate(l)...)
	}
	recursivesort.Sort(&result)
	return result
}

func All() Validators {
	return Validators{
		ValidatorActorsAreProtected{},
		ValidatorFinalCoverageIsComplete{},
		ValidatorNoIssues{},
	}
}
