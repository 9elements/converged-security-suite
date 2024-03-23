package displayeventlog

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/exp/pcr0tool/commands/displayeventlog/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

func usageAndExit() {
	flag.Usage()
	os.Exit(2)
}

// Command is the implementation of `commands.Command`.
type Command struct {
	eventLog *string
	pcrIndex *int64
	hashAlgo *int64
	calcPCR  *bool
	format   flagFormat
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "display TPM Event Log"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.eventLog = flag.String("event-log", "/sys/kernel/security/tpm0/binary_bios_measurements", "path to the binary EventLog")
	cmd.pcrIndex = flag.Int64("pcr-index", -1, "filter for specific PCR register")
	cmd.hashAlgo = flag.Int64("hash-algo", 0, "filter by hash algorithm")
	cmd.calcPCR = flag.Bool("calc-pcr", false, "should calculate the PCR value")
	flag.Var(&cmd.format, "format", "select output format, allowed values: plaintext-oneline, plaintext-multiline")
}

func ptr[T any](in T) *T {
	return &in
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, args []string) {
	if len(args) > 0 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: too many parameters\n")
		usageAndExit()
	}

	eventLogFile, err := os.Open(*cmd.eventLog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to open EventLog '%s': %v", *cmd.eventLog, err)
		return
	}

	eventLog, err := tpmeventlog.Parse(eventLogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to parse EventLog '%s': %v", *cmd.eventLog, err)
		return
	}

	if *cmd.calcPCR && (*cmd.pcrIndex == -1 || *cmd.hashAlgo == 0) {
		fmt.Fprintf(os.Stderr, "to calculate a PCR value it is required to set PCR index (-pcr-index) and hash algorithm (-hash-algo)")
		return
	}

	var filterPCRIndex *pcr.ID
	var filterHashAlgo *tpmeventlog.TPMAlgorithm
	if *cmd.pcrIndex != -1 {
		filterPCRIndex = ptr(pcr.ID(*cmd.pcrIndex))
	}
	if *cmd.hashAlgo != 0 {
		filterHashAlgo = format.HashAlgoPtr(tpmeventlog.TPMAlgorithm(*cmd.hashAlgo))
	}
	fmt.Print(format.EventLog(eventLog, filterPCRIndex, filterHashAlgo, "", cmd.format == flagFormatPlaintextMultiline))

	if *cmd.calcPCR {
		calculatedValue, err := tpmeventlog.Replay(eventLog, pcr.ID(*cmd.pcrIndex), tpmeventlog.TPMAlgorithm(*cmd.hashAlgo), nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to replay the PCR%d value: %v", *cmd.pcrIndex, err)
			return
		}
		fmt.Printf("Calc\t%2d\t%10s\t%3d\t%X\t\n", *cmd.pcrIndex, "", *cmd.hashAlgo, calculatedValue)
	}
}
