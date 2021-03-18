package check

import (
	"github.com/9elements/converged-security-suite/v2/pkg/errors"
)

func bounds(length uint, startIdx, endIdx int) error {
	result := &errors.MultiError{}
	if startIdx < 0 {
		result.Add(&errors.ErrStartLessThanZero{StartIdx: startIdx})
	}
	if endIdx < startIdx {
		result.Add(&errors.ErrEndLessThanStart{StartIdx: startIdx, EndIdx: endIdx})
	}
	if endIdx >= 0 && uint(endIdx) > length {
		result.Add(&errors.ErrEndGreaterThanLength{Length: length, EndIdx: endIdx})
	}

	return result.ReturnValue()
}

// BytesRange checks if starting index `startIdx`, ending index `endIdx` and
// len(b) passes sanity checks:
// * 0 <= startIdx
// * startIdx <= endIdx
// * endIdx < len(b)
func BytesRange(b []byte, startIdx, endIdx int) error {
	return bounds(uint(len(b)), startIdx, endIdx)
}
