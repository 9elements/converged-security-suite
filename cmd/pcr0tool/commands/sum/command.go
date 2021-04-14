package sum

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"log"
	"os"
	"strings"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/google/go-tpm/tpm2"
)

func usageAndExit() {
	flag.Usage()
	os.Exit(2)
}

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// Command is the implementation of `commands.Command`.
type Command struct {
	isQuiet   *bool
	flow      *string
	hashFunc  *string
	registers helpers.FlagRegisters
	tpmDevice *string

	printMeasurementLengthLimit *uint
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<firmware>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "calculate the expected value of PCR0 for a specified firmware image"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.isQuiet = flag.Bool("quiet", false, `display only the result`)
	cmd.flow = flag.String("flow", pcr.FlowAuto.String(), "values: "+commands.FlowCommandLineValues())
	cmd.hashFunc = flag.String("hash-func", "sha1", `which hash function use to hash measurements and to extend the PCR0; values: "sha1", "sha256"`)
	flag.Var(&cmd.registers, "registers", "[optional] file that contains registers as a json array (use value '/dev' to use registers of the local machine)")
	cmd.tpmDevice = flag.String("tpm-device", "", "[optional] tpm device used for measurements, values: "+commands.TPMTypeCommandLineValues())
	cmd.printMeasurementLengthLimit = flag.Uint("print-measurement-length-limit", 20, "length limit of measured data to be printed")
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: no path to the firmare was specified\n")
		usageAndExit()
	}
	if len(args) > 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: too many parameters\n")
		usageAndExit()
	}
	imagePath := args[0]

	flow, err := pcr.FlowFromString(*cmd.flow)
	if err != nil {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "unknown attestation flow: '%s'\n", *cmd.flow)
		usageAndExit()
	}

	var measureOpts []pcr.MeasureOption
	measureOpts = append(measureOpts, pcr.SetFlow(flow))
	measureOpts = append(measureOpts, pcr.SetRegisters(cmd.registers))

	var hashFunc hash.Hash
	hashFuncString := strings.ToLower(*cmd.hashFunc)
	switch hashFuncString {
	case "sha1", "":
		hashFunc = sha1.New()
		measureOpts = append(measureOpts, pcr.SetIBBHashDigest(tpm2.AlgSHA1))
	case "sha256":
		hashFunc = sha256.New()
		measureOpts = append(measureOpts, pcr.SetIBBHashDigest(tpm2.AlgSHA256))
	default:
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: invalid value of option 'hash-func': '%s'\n", hashFuncString)
		usageAndExit()
	}

	if len(*cmd.tpmDevice) > 0 {
		tpmDevice, err := tpmdetection.FromString(*cmd.tpmDevice)
		if err != nil {
			usageAndExit()
		}
		measureOpts = append(measureOpts, pcr.SetTPMDevice(tpmDevice))
	}

	firmware, err := uefi.ParseUEFIFirmwareFile(imagePath)
	assertNoError(err)

	measurements, flow, debugInfo, err := pcr.GetMeasurements(firmware, 0, measureOpts...)
	var pcrLogger pcr.Printfer
	if !*cmd.isQuiet {
		debugInfoBytes, err := json.MarshalIndent(debugInfo, "", "  ")
		assertNoError(err)
		measurementsBytes, _ := json.MarshalIndent(measurements, "", "  ")

		fmt.Println("debugInfo:", string(debugInfoBytes))
		fmt.Println("measurements:", string(measurementsBytes))

		pcrLogger = log.New(os.Stdout, "", 0)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "GetPCRMeasurements error: %v\n", err)
	}
	if measurements == nil {
		os.Exit(1)
	}
	pcr.LoggingDataLimit = *cmd.printMeasurementLengthLimit
	result := measurements.Calculate(firmware.Buf(), flow.TPMLocality(), hashFunc, pcrLogger)

	if !*cmd.isQuiet {
		fmt.Printf("Resulting PCR0: ")
	}
	fmt.Printf("%X\n", result)
}
