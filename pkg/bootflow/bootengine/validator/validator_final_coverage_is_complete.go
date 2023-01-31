package validator

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
)

type ValidatorFinalCoverageIsComplete struct{}

var _ Validator = (*ValidatorFinalCoverageIsComplete)(nil)

func (ValidatorFinalCoverageIsComplete) Validate(l bootengine.Log) Issues {
	return nil
}
