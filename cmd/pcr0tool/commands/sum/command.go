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
	"github.com/9elements/converged-security-suite/v2/pkg/pcrbruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
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
	isQuiet             *bool
	flow                *string
	hashFunc            *string
	registers           helpers.FlagRegisters
	tpmDevice           *string
	compareWithEventLog *string

	printMeasurementLengthLimit *uint

	// Intel-specific advanced options
	decrementACMPolicyStatus *uint
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
	cmd.compareWithEventLog = flag.String("compare-with-eventlog", "", "[optional] compare expected measurements with a TPM EventLog")
	cmd.printMeasurementLengthLimit = flag.Uint("print-measurement-length-limit", 20, "length limit of measured data to be printed")
	cmd.decrementACMPolicyStatus = flag.Uint("decrement-acm-policy-status", 0, "[advanced] decrement Intel ACM Policy Status value")
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

	if *cmd.decrementACMPolicyStatus != 0 {
		found := false
		for idx, reg := range cmd.registers {
			switch reg := reg.(type) {
			case registers.ACMPolicyStatus:
				cmd.registers[idx] = reg - registers.ACMPolicyStatus(*cmd.decrementACMPolicyStatus)
				found = true
			}
		}
		if !found {
			_, _ = fmt.Fprintf(flag.CommandLine.Output(), "cannot decrement ACM Policy Status, because the register wasn't found\n")
			usageAndExit()
		}
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

	if *cmd.compareWithEventLog != "" {
		fmt.Println()

		if *cmd.hashFunc != "sha1" {
			panic("comparing with TPM EventLog is currently supported only for SHA1 digests")
		}
		f, err := os.Open(*cmd.compareWithEventLog)
		assertNoError(err)
		tpmEventLog, err := tpmeventlog.Parse(f)
		assertNoError(err)
		match, updatedACMPolicyStatus, issues, err := pcrbruteforcer.ReproduceEventLog(tpmEventLog, tpmeventlog.TPMAlgorithmSHA1, measurements, firmware.Buf(), pcrbruteforcer.DefaultSettingsReproduceEventLog())
		fmt.Printf("comparing with TPM EventLog result:\n\tmatch: %v\n\tupdated ACM Policy Status: %v\n\terr: %v\n\tissues:\n%s\n",
			match, updatedACMPolicyStatus, err, formatIssues(issues, "\t\t"))
	}
}

func formatIssues(issues []pcrbruteforcer.Issue, intend string) string {
	if len(issues) == 0 {
		return "NONE"
	}
	var result strings.Builder
	for _, issue := range issues {
		result.WriteString(fmt.Sprintf("%s* %s\n", intend, issue.Error()))
	}
	return result.String()
}
