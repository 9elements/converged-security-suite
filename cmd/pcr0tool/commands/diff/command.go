package diff

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/diff/format"
	pkgbytes "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/ostools"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
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

type outputFormatType int

const (
	outputFormatTypeUnknown = outputFormatType(iota)
	outputFormatTypeAnalyzedText
	outputFormatTypeAnalyzedJSON
	outputFormatTypeJSON
)

func parseOutputFormatType(s string) outputFormatType {
	switch s {
	case "analyzed-json":
		return outputFormatTypeAnalyzedJSON
	case "analyzed-text":
		return outputFormatTypeAnalyzedText
	case "json":
		return outputFormatTypeJSON
	}
	return outputFormatTypeUnknown
}

func parseByteSet(s string) ([]byte, error) {
	if s == `` {
		return nil, nil
	}
	var ignoreByteSet []byte
	for _, char := range strings.Split(s, `,`) {
		decoded, err := hex.DecodeString(char)
		if err != nil {
			return nil, fmt.Errorf("unable to decode HEX value '%s'", char)
			os.Exit(1)
		}
		if len(decoded) != 1 {
			return nil, fmt.Errorf("unexpected length of a character '%s' (%d != 1)", char, len(decoded))
		}
		ignoreByteSet = append(ignoreByteSet, decoded[0])
	}
	return ignoreByteSet, nil
}

// Command is the implementation of `commands.Command`.
type Command struct {
	forceScanArea *string
	ignoreByteSet *string
	outputFormat  *string
	flow          *string
	netPprof      *string
	deepAnalysis  *bool
	registers     *string
	hashFunc      *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<firmware_good> <firmware_bad>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "find the reason of different PCR0 values between two firmware images"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.forceScanArea = flag.String("force-scan-area", "",
		`Force the scan area instead of following the PCR0 calculation. Values: "" (follow the PCR0 calculation), "bios_region"`)
	cmd.ignoreByteSet = flag.String("ignore-byte-set", "", `Define a set of bytes to ignore while the comparison. 
It makes sense to use this option together with "-force-scan-area bios_region" to scan the whole image, 
but ignore the overridden bytes. The value is represented in hex characters separated by comma, for example: "00,ff". Default: ""`)
	cmd.outputFormat = flag.String("output-format", "analyzed-text", `Values: "analyzed-text", "analyzed-json", "json"`)
	cmd.flow = flag.String("flow", "auto", "values: "+commands.FlowCommandLineValues())
	cmd.deepAnalysis = flag.Bool("deep-analysis", false,
		`Also perform slow procedures to find more byte ranges which could affect the PCR0 calculation. This is experimental feature! Values: "true", "false"`)
	cmd.netPprof = flag.String("net-pprof", "", `start listening for "net/http/pprof", example value: "127.0.0.1:6060"`)
	cmd.registers = flag.String("registers", "", "[optional] file that contains registers as a json array")
	cmd.hashFunc = flag.String("hash-func", "", `which hash function use to hash measurements and to extend the PCR0; values: "sha1", "sha256"`)
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(args []string) {
	if len(args) != 2 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "expected amount of arguments is two, but received: %d\n", len(args))
		usageAndExit()
	}

	outputFormat := parseOutputFormatType(*cmd.outputFormat)
	if outputFormat == outputFormatTypeUnknown {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "unknown output format type: '%s'\n", *cmd.outputFormat)
		usageAndExit()
	}

	flow, err := pcr.FlowFromString(*cmd.flow)
	if err != nil {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "unknown attestation flow: '%s'\n", *cmd.flow)
		usageAndExit()
	}

	var measureOpts []pcr.MeasureOption
	measureOpts = append(measureOpts, pcr.SetFlow(flow))

	if *cmd.deepAnalysis {
		measureOpts = append(measureOpts, pcr.SetFindMissingFakeMeasurements(true))
	}

	if *cmd.netPprof != "" {
		go func() {
			log.Println(http.ListenAndServe(*cmd.netPprof, nil))
		}()
	}

	ignoreByteSet, err := parseByteSet(*cmd.ignoreByteSet)
	assertNoError(err)

	var regs registers.Registers
	if len(*cmd.registers) > 0 {
		contents, err := ioutil.ReadFile(*cmd.registers)
		assertNoError(err)
		err = json.Unmarshal(contents, &regs)
		assertNoError(err)
	}
	measureOpts = append(measureOpts, pcr.SetRegisters(regs))

	switch strings.ToLower(*cmd.hashFunc) {
	case "sha1":
		measureOpts = append(measureOpts, pcr.SetIBBHashDigest(tpm2.AlgSHA1))
	case "sha256":
		measureOpts = append(measureOpts, pcr.SetIBBHashDigest(tpm2.AlgSHA256))
	}

	firmwareGood, err := uefi.ParseUEFIFirmwareFile(args[0])
	assertNoError(err)
	firmwareGoodData := firmwareGood.Buf()

	firmwareBadData, err := ostools.FileToBytes(args[1])
	if firmwareBadData == nil {
		assertNoError(err)
	}

	measurements, _, debugInfo, err := pcr.GetMeasurements(firmwareGood, 0, measureOpts...)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "GetPCRMeasurements error: %v\n", err)
	}
	if measurements == nil {
		os.Exit(1)
	}

	var scanRanges pkgbytes.Ranges
	switch *cmd.forceScanArea {
	case `bios_region`:
		nodes, err := firmwareGood.GetByRegionType(fianoUEFI.RegionTypeBIOS)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to find bios_region, error: %v\n", err)
			os.Exit(1)
		}
		for _, r := range nodes {
			if r.Offset == math.MaxUint64 {
				_, _ = fmt.Fprintf(os.Stderr, "Unable to detect the offset of the node\n")
				continue
			}
			scanRanges = append(scanRanges, r.Range)
		}
	case ``:
		chunks := measurements.Data()
		for idx := range chunks {
			if chunks[idx].Range.Length == 0 {
				continue
			}
			scanRanges = append(scanRanges, chunks[idx].Range)
		}
	}
	if len(scanRanges) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Nothing to compare :(\n")
		os.Exit(1)
	}
	debugInfo["scanRanges"] = scanRanges

	diffEntries := diff.Diff(scanRanges, firmwareGoodData, firmwareBadData, ignoreByteSet)

	switch outputFormat {
	case outputFormatTypeAnalyzedText:
		output, err := format.AsText(
			diff.Analyze(diffEntries, measurements, firmwareGood, firmwareBadData),
			debugInfo, measurements, firmwareGoodData, firmwareBadData,
		)
		assertNoError(err)
		fmt.Print(output)
	case outputFormatTypeAnalyzedJSON:
		outputAnalyzedJSON(
			diff.Analyze(diffEntries, measurements, firmwareGood, firmwareBadData),
			debugInfo, measurements,
		)
	case outputFormatTypeJSON:
		outputJSON(diffEntries, debugInfo, measurements)
	}
}

// MeasurementsLaconic is a helper to print measurements in a laconic way
type MeasurementsLaconic pcr.Measurements

func (s MeasurementsLaconic) String() string {
	var ids []string
	for _, measurement := range s {
		ids = append(ids, measurement.ID.String())
	}
	return strings.Join(ids, ", ")
}

func outputAnalyzedJSON(
	report diff.AnalysisReport,
	debugInfo map[string]interface{},
	measurements pcr.Measurements,
) {
	jsonData, err := json.MarshalIndent(struct {
		Report       diff.AnalysisReport
		DebugInfo    map[string]interface{}
		Measurements pcr.Measurements
	}{report, debugInfo, measurements}, ``, ` `)
	assertNoError(err)
	fmt.Printf("%s", jsonData)
}

func outputJSON(
	diffRanges []pkgbytes.Range,
	debugInfo map[string]interface{},
	measurements []*pcr.Measurement,
) {
	diffJSON, err := json.MarshalIndent(&struct {
		DebugInfo    interface{}
		Measurements interface{}
		Diff         interface{}
	}{
		DebugInfo:    debugInfo,
		Measurements: measurements,
		Diff:         diffRanges,
	}, "", " ")
	assertNoError(err)

	fmt.Printf("%s\n", diffJSON)
}
