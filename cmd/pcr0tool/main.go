package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands"
	bruteforceacmpolicystatus "github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/bruteforce_acm_policy_status"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/diff"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/displayeventlog"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/displayfwinfo"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpfit"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/printnodes"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/sum"
	validatesecurity "github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/validate_security"
	"github.com/9elements/converged-security-suite/v2/pkg/log"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

var knownCommands = map[string]commands.Command{
	"bruteforce_acm_policy_status": &bruteforceacmpolicystatus.Command{},
	"diff":                         &diff.Command{},
	"display_eventlog":             &displayeventlog.Command{},
	"display_fwinfo":               &displayfwinfo.Command{},
	"dump_fit":                     &dumpfit.Command{},
	"dump_registers":               &dumpregisters.Command{},
	"printnodes":                   &printnodes.Command{},
	"validate_security":            &validatesecurity.Command{},
	"sum":                          &sum.Command{},
}

func usageAndExit() {
	flag.Usage()
	os.Exit(2) // the standard Go's exit-code on invalid flags
}

var logLevel = logger.LevelWarning

func setupFlag() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "syntax: pcr0tool <command> [options] {arguments}\n")
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\nPossible commands:\n")
		var verbs []string
		for commandName := range knownCommands {
			verbs = append(verbs, commandName)
		}
		sort.Strings(verbs)
		for _, commandName := range verbs {
			command := knownCommands[commandName]
			_, _ = fmt.Fprintf(flag.CommandLine.Output(), "    pcr0tool %-36s%s\n",
				fmt.Sprintf("%s %s", commandName, command.Usage()), command.Description())
		}
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\n")
	}

	flag.Var(&logLevel, "log-level", "")
	flag.Parse()
	if flag.NArg() < 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: no command specified\n\n")
		usageAndExit()
	}
}

func main() {
	cbnt.StrictOrderCheck = false // some firmwares have incorrect elements order, should parse them anyway
	setupFlag()

	ctx := logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logLevel))
	fianoLog.DefaultLogger = log.NewFianoLogger(logger.FromCtx(ctx), logger.LevelTrace)

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
	_ = flagSet.Parse(os.Args[len(os.Args)-flag.NArg()+1:])
	command.Execute(ctx, flagSet.Args())
}
