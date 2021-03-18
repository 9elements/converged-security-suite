package errors

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MultiError is a type which aggregates multiple `error`-s into one `error`.
//
// Some functions may have multiple errors at one call, and sometimes
// we don't want to lose them (so we collect them all).
type MultiError []error

func (mErr MultiError) Error() string {
	if mErr.Count() == 0 {
		return "no errors"
	}
	var errStrings []string
	for _, err := range mErr {
		errStrings = append(errStrings, err.Error())
	}
	return fmt.Sprintf("errors: %v", strings.Join(errStrings, "; "))
}

// MarshalJSON just implements encoding/json.Marshaler
func (mErr MultiError) MarshalJSON() ([]byte, error) {
	if len(mErr) == 0 {
		return []byte("null"), nil
	}

	return json.Marshal(mErr.Error())
}

// Add adds errors to the collection.
//
// If some of passed errors are nil, then they won't be added
// (a `nil` error is not considered to be an error).
func (mErr *MultiError) Add(errs ...error) *MultiError {
	for _, err := range errs {
		if err == nil {
			continue
		}
		switch err := err.(type) {
		case *MultiError:
			if err == nil {
				continue
			}
			*mErr = append(*mErr, *err...)
		case MultiError:
			*mErr = append(*mErr, err...)
		default:
			*mErr = append(*mErr, err)
		}
	}

	return mErr
}

// Count returns the amount of collected errors.
func (mErr MultiError) Count() uint {
	return uint(len(mErr))
}

// ReturnValue is a helper which returns `nil` if there was
// no errors collected, and the collection if there're any.
//
// It supposed to be used in `return`-s:
//     return mErr.ReturnValue()
func (mErr MultiError) ReturnValue() error {
	if mErr.Count() > 0 {
		return mErr
	}

	return nil
}

// Filter returns a copy of mErr but only with entries on which function "fn"
// returns "true".
func (mErr MultiError) Filter(fn func(err error) bool) MultiError {
	var result MultiError
	for _, err := range mErr {
		if fn(err) {
			result = append(result, err)
		}
	}
	return result
}

// Unwrap is used by functions like `errors.As()`. Since it is not allowed
// to return multiple errors, it unwraps an error if there's only one.
func (mErr MultiError) Unwrap() error {
	if mErr.Count() == 1 {
		return mErr[0]
	}
	return nil
}
