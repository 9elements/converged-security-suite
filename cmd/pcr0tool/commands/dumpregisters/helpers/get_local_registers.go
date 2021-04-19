package helpers

import (
	"fmt"
	"runtime"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/hwapi"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

// GetLocalRegisters extract registers from the local machine.
func GetLocalRegisters() (registers.Registers, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("command is supported only on Linux platform")
	}

	txtAPI := hwapi.GetAPI()

	txtConfig, err := registers.FetchTXTConfigSpace(txtAPI)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch TXT public space: %w", err)
	}

	txtRegisters, txtErr := registers.ReadTXTRegisters(txtConfig)
	msrRegisters, msrErr := txtAPI.GetMSRRegisters()
	allRegisters := append(txtRegisters, msrRegisters...)

	return allRegisters, (&errors.MultiError{}).Add(txtErr, msrErr).ReturnValue()
}
