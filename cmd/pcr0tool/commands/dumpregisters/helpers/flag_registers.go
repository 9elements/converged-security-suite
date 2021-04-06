package helpers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
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
		return nil
	case "/dev":
		regs, err := GetLocalRegisters()
		if err != nil && regs == nil {
			return fmt.Errorf("unable to get register values of the local machine: %w", err)
		}
		*f = FlagRegisters(regs)
		return nil
	default:
		contents, err := ioutil.ReadFile(in)
		if err != nil {
			return fmt.Errorf("unable to parse file '%s': %w", in, err)
		}
		err = json.Unmarshal(contents, f)
		if err != nil {
			return fmt.Errorf("unable to unmarshal JSON from file '%s': %w", in, err)
		}
		return nil
	}
}
