package dumpregisters

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	outputFile *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "dump status registers from /dev/mem and /dev/cpu/0/msr. Works only on Linux"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.outputFile = flag.String("output", "",
		"[optional] dumps all registers into a file")
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(args []string) {
	regs, err := helpers.GetLocalRegisters()
	if regs == nil && err != nil {
		panic(err)
	}
	helpers.PrintRegisters(regs)

	if len(*cmd.outputFile) > 0 {
		b, err := json.Marshal(regs)
		if err != nil {
			panic(fmt.Sprintf("failed to marshal registers into json, err: %v", err))
		}
		err = ioutil.WriteFile(*cmd.outputFile, b, 0666)
		if err != nil {
			panic(fmt.Sprintf("failed to write data to file %s, err: %v", *cmd.outputFile, err))
		}
	}
}
