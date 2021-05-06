package pcr

import (
	"fmt"
)

// ValidateFlow is a sequence of validators.
type ValidateFlow []Validator

// Validate sequentially executes all validators of the flow and returns
// an error on the first error returned by a validator. If no errors received,
// then no error is returned.
func (s ValidateFlow) Validate(firmware Firmware) error {
	for _, validator := range s {
		err := validator.Validate(firmware)
		if err != nil {
			return fmt.Errorf("validator %T failed: %w", validator, err)
		}
	}

	return nil
}

// Validator is the interface of a checker if specific measurement
// flow could be executed on a specific firmware.
type Validator interface {
	// Validate returns nil if firmware could be used in the measurement flow.
	Validate(firmware Firmware) error
}
