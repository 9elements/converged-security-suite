package dumpregisters

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/exp/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"

	"gopkg.in/yaml.v3"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	outputFile    *string
	txtPublicDump *string
	registers     helpers.FlagRegisters
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
	cmd.txtPublicDump = flag.String("txt-public-dump", "",
		"[optional] override TXT public space with a file")
	flag.Var(&cmd.registers, "registers", "[optional] file that contains registers as a json array (use value '/dev' to use registers of the local machine)")
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, args []string) {
	if *cmd.txtPublicDump != "" && cmd.registers != nil {
		panic(fmt.Errorf("cannot use flags -txt-public-dump and -registers together"))
	}
	var (
		regs registers.Registers
		err  error
	)
	if cmd.registers != nil {
		regs = registers.Registers(cmd.registers)
	} else {
		getRegistersOpts := []helpers.GetRegistersOption{helpers.OptLocalhostByDefault(true)}
		if *cmd.txtPublicDump != "" {
			getRegistersOpts = append(getRegistersOpts, helpers.OptTXTPublic(*cmd.txtPublicDump))
		}
		regs, err = helpers.GetRegisters(getRegistersOpts...)
	}
	if regs == nil && err != nil {
		panic(err)
	}
	helpers.PrintRegisters(regs)

	if len(*cmd.outputFile) > 0 {
		b, err := yaml.Marshal(regs)
		if err != nil {
			panic(fmt.Sprintf("failed to marshal registers into json, err: %v", err))
		}
		err = os.WriteFile(*cmd.outputFile, b, 0o666)
		if err != nil {
			panic(fmt.Sprintf("failed to write data to file %s, err: %v", *cmd.outputFile, err))
		}
	}
}
