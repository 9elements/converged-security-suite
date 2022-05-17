package helpers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
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
		contents, err := ioutil.ReadFile(in)
		if err != nil {
			return fmt.Errorf("unable to parse file '%s': %w", in, err)
		}

		// ===
		// TODO: Remove the JSON format, it is added only for backward compatibility
		//       In year like 2025 this should be deleted.
		err = json.Unmarshal(contents, (*registers.Registers)(f))
		if err == nil {
			return nil
		}
		// ===

		err = yaml.Unmarshal(contents, (*registers.Registers)(f))
		if err != nil {
			return fmt.Errorf("unable to unmarshal YAML from file '%s': %w", in, err)
		}
		return nil
	}
}
