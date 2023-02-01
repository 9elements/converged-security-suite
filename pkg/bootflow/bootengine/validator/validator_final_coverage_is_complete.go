package validator

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
)

// ValidatorFinalCoverageIsComplete check if all PE32 files are protected.
type ValidatorFinalCoverageIsComplete struct{}

var _ Validator = (*ValidatorFinalCoverageIsComplete)(nil)

func (ValidatorFinalCoverageIsComplete) Validate(l bootengine.Log) Issues {
	// TODO: implement.
	return nil
}
