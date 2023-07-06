package pcrread

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpm"
)

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func usageAndExit() {
	flag.Usage()
	os.Exit(2)
}

// Command is the implementation of `commands.Command`.
type Command struct {
	hashAlgo *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<PCR index>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "read the PCR value"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.hashAlgo = flag.String("hash-algo", tpm2.AlgSHA1.String(), "")
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: no PCR index is specified\n")
		usageAndExit()
	}
	if len(args) > 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: too many parameters\n")
		usageAndExit()
	}
	pcrIndexString := args[0]
	pcrIndex, err := strconv.ParseUint(pcrIndexString, 10, 64)
	assertNoError(err)

	hashAlgo := tpm2.AlgUnknown
	for _, alg := range []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256} {
		if strings.EqualFold(*cmd.hashAlgo, alg.String()) {
			hashAlgo = alg
		}
	}
	if hashAlgo == tpm2.AlgUnknown {
		panic(fmt.Errorf("algo '%s' is unknown", *cmd.hashAlgo))
	}
	pcr, err := tpm.ReadPCRFromTPM(pcr.ID(pcrIndex), hashAlgo)
	assertNoError(err)
	fmt.Printf("%X\n", pcr)
}
