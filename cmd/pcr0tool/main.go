package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/diff"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpfit"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/printnodes"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/sum"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
)

var knownCommands = map[string]commands.Command{
	"diff":           &diff.Command{},
	"dump_fit":       &dumpfit.Command{},
	"dump_registers": &dumpregisters.Command{},
	"printnodes":     &printnodes.Command{},
	"sum":            &sum.Command{},
}

func usageAndExit() {
	flag.Usage()
	os.Exit(2) // the standard Go's exit-code on invalid flags
}

func setupFlag() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "syntax: pcr0tool <command> [options] {arguments}\n")
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\nPossible commands:\n")
		for commandName, command := range knownCommands {
			_, _ = fmt.Fprintf(flag.CommandLine.Output(), "    pcr0tool %-36s%s\n",
				fmt.Sprintf("%s %s", commandName, command.Usage()), command.Description())
		}
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\n")
	}

	flag.Parse()
	if flag.NArg() < 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: no command specified\n\n")
		usageAndExit()
	}
}

func main() {
	manifest.StrictOrderCheck = false // some firmwares have incorrect elements order, should parse them anyway

	setupFlag()

	commandName := flag.Arg(0)
	command := knownCommands[commandName]
	if command == nil {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: unknown command '%s'\n\n", commandName)
		usageAndExit()
	}

	flagSet := flag.NewFlagSet(commandName, flag.ExitOnError)
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "syntax: pcr0tool %s [options] %s\n\nOptions:\n",
			commandName, command.Usage())
		flagSet.PrintDefaults()
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\n")
	}

	flag.Usage = flagSet.Usage // so a the "command" could just call `flag.Usage()` to print it's usage

	command.SetupFlagSet(flagSet)
	_ = flagSet.Parse(os.Args[2:])
	command.Execute(flagSet.Args())
}
