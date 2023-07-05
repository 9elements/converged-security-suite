package helpers

import (
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/hashicorp/go-multierror"
	"gopkg.in/yaml.v3"
)

// FlagRegisters is a flag.Value implementation to enter status registers.
type FlagRegisters registers.Registers

// String implements flag.Value
func (f *FlagRegisters) String() string {
	return ""
}

// Set implements flag.Value
func (f *FlagRegisters) Set(in string) error {
	switch in {
	case "":
		// We do not fallthrough to "/dev" here to do not mislead the end user.
		//
		// The user should explicitly ask to use local-machine registers to
		// do not mislead them about expected PCR0 value on CBnT systems.
		// Otherwise the user might not know that the value is constructed
		// using local values.
		return nil
	case "/dev":
		regs, err := GetRegisters(OptLocalhostByDefault(true))
		if err != nil && regs == nil {
			return fmt.Errorf("unable to get register values of the local machine: %w", err)
		}
		*f = FlagRegisters(regs)
		return nil
	default:
		contents, err := os.ReadFile(in)
		if err != nil {
			return fmt.Errorf("unable to parse file '%s': %w", in, err)
		}

		var mErr error
		err = yaml.Unmarshal(contents, (*registers.Registers)(f))
		if err == nil {
			return nil
		}
		mErr = multierror.Append(mErr, err)

		err = parseBinaryTXTPublicSpace(contents, (*registers.Registers)(f))
		if err == nil {
			return nil
		}
		mErr = multierror.Append(mErr, err)

		return fmt.Errorf("do not know how to parse '%s': %w", in, mErr)
	}
}

func parseBinaryTXTPublicSpace(contents []byte, regs *registers.Registers) error {
	if len(contents) != 1<<16 {
		return fmt.Errorf("expected TXT public space is %d; but the content has size %d", 1<<16, len(contents))
	}

	newRegs, err := registers.ReadTXTRegisters(registers.TXTConfigSpace(contents))
	if err != nil {
		return fmt.Errorf("unable to read the TXT registers: %w", err)
	}

	*regs = newRegs
	return nil
}
