package diff

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/cmd/exp/pcr0tool/commands"
	"github.com/9elements/converged-security-suite/v2/cmd/exp/pcr0tool/commands/diff/format"
	"github.com/9elements/converged-security-suite/v2/cmd/exp/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	bfformat "github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/amdpsp"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/amdregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/ostools"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
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

// Command is the implementation of `commands.Command`.
type Command struct {
	forceScanArea *string
	ignoreByteSet *string
	outputFormat  *string
	flow          *string
	netPprof      *string
	registers     helpers.FlagRegisters
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<firmware_good> <firmware_bad>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "find a corruption in a firmware which causes different PCR values"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.forceScanArea = flag.String("force-scan-area", "", `Force the scan area instead of following the PCR0 calculation. Values: "" (follow the PCR0 calculation), "bios_region"`)
	cmd.ignoreByteSet = flag.String("ignore-byte-set", "", `Define a set of bytes to ignore while the comparison. 
It makes sense to use this option together with "-force-scan-area bios_region" to scan the whole image, 
but ignore the overridden bytes. The value is represented in hex characters separated by comma, for example: "00,ff". Default: ""`)
	cmd.outputFormat = flag.String("output-format", "analyzed-text", `Values: "analyzed-text", "analyzed-json", "json"`)
	cmd.flow = flag.String("flow", flows.Root.Name, "values: "+commands.FlowCommandLineValues())
	cmd.netPprof = flag.String("net-pprof", "", `start listening for "net/http/pprof", example value: "127.0.0.1:6060"`)
	flag.Var(&cmd.registers, "registers", "[optional] file that contains registers as a json array (use value '/dev' to use registers of the local machine)")
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
		}
		if len(decoded) != 1 {
			return nil, fmt.Errorf("unexpected length of a character '%s' (%d != 1)", char, len(decoded))
		}
		ignoreByteSet = append(ignoreByteSet, decoded[0])
	}
	return ignoreByteSet, nil
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, args []string) {
	if len(args) != 2 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "expected amount of arguments is two, but received: %d\n", len(args))
		usageAndExit()
	}

	outputFormat := parseOutputFormatType(*cmd.outputFormat)
	if outputFormat == outputFormatTypeUnknown {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "unknown output format type: '%s'\n", *cmd.outputFormat)
		usageAndExit()
	}

	state := types.NewState()
	state.IncludeSubSystem(tpm.NewTPM())
	state.IncludeSubSystem(intelpch.NewPCH())
	state.IncludeSubSystem(amdpsp.NewPSP())

	flow, ok := flows.GetFlowByName(*cmd.flow)
	if !ok {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "unknown boot flow: '%s'\n", *cmd.flow)
		usageAndExit()
	}

	state.SetFlow(flow)

	if *cmd.netPprof != "" {
		go func() {
			log.Println(http.ListenAndServe(*cmd.netPprof, nil))
		}()
	}

	state.IncludeSystemArtifact(txtpublic.New(registers.Registers(cmd.registers)))
	state.IncludeSystemArtifact(amdregisters.New(registers.Registers(cmd.registers)))

	firmwareGoodData, err := ostools.FileToBytes(args[0])
	assertNoError(err)
	firmwareGood := biosimage.New(firmwareGoodData)

	firmwareBadData, err := ostools.FileToBytes(args[1])
	assertNoError(err)
	firmwareBad := biosimage.New(firmwareBadData)

	state.IncludeSystemArtifact(firmwareGood)
	process := bootengine.NewBootProcess(state)
	process.Finish(ctx)
	err = process.Log.Error()
	assertNoError(err)

	measurements := process.CurrentState.MeasuredData

	// we use mem ranges instead of ranges in a file, because two files
	// might be unaligned one to another.
	var memRanges pkgbytes.Ranges

	switch *cmd.forceScanArea {
	case `bios_region`:
		firmwareGoodUEFI, err := firmwareGood.Parse()
		assertNoError(err)
		nodes, err := firmwareGoodUEFI.GetByRegionType(fianoUEFI.RegionTypeBIOS)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to find bios_region, error: %v\n", err)
			os.Exit(1)
		}
		var fileRanges pkgbytes.Ranges
		for _, r := range nodes {
			if r.Offset == math.MaxUint64 {
				_, _ = fmt.Fprintf(os.Stderr, "Unable to detect the offset of the node\n")
				continue
			}
			fileRanges = append(fileRanges, r.Range)
		}
		memRanges, err = biosimage.PhysMemMapper{}.Unresolve(firmwareGood, fileRanges...)
		assertNoError(err)
	case ``:
		biosRefs := measurements.References().BySystemArtifact(firmwareGood)
		for _, ref := range biosRefs {
			ranges := ref.MappedRanges.Ranges
			if ref.MappedRanges.AddressMapper != (biosimage.PhysMemMapper{}) {
				resolvedRanges, err := ref.ResolvedRanges()
				assertNoError(err)
				ranges, err = biosimage.PhysMemMapper{}.Unresolve(firmwareGood, resolvedRanges...)
				assertNoError(err)
			}
			for _, r := range ranges {
				if r.Length == 0 {
					continue
				}
				memRanges = append(memRanges, r)
			}
		}
	}
	if len(memRanges) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Nothing to compare :(\n")
		os.Exit(1)
	}
	debugInfo := map[string]any{}
	debugInfo["scanRanges"] = memRanges

	ignoreByteSet, err := parseByteSet(*cmd.ignoreByteSet)
	assertNoError(err)
	diffEntries, err := diff.Diff(memRanges, biosimage.PhysMemMapper{}, firmwareGood, firmwareBad, ignoreByteSet)
	assertNoError(err)

	switch outputFormat {
	case outputFormatTypeAnalyzedText:
		report, err := diff.Analyze(diffEntries, biosimage.PhysMemMapper{}, measurementsForDiffAnalysis(measurements, firmwareGood), firmwareGood, firmwareBad)
		assertNoError(err)
		output, err := format.AsText(report, debugInfo, firmwareGood, firmwareBad)
		assertNoError(err)
		fmt.Print(output)
	case outputFormatTypeAnalyzedJSON:
		report, err := diff.Analyze(diffEntries, biosimage.PhysMemMapper{}, measurementsForDiffAnalysis(measurements, firmwareGood), firmwareGood, firmwareBad)
		assertNoError(err)
		outputAnalyzedJSON(
			report,
			debugInfo, measurements,
		)
	case outputFormatTypeJSON:
		outputJSON(diffEntries, debugInfo, measurements)
	default:
		panic(outputFormat)
	}
}

func measurementsForDiffAnalysis(
	ms types.MeasuredDataSlice,
	filterSystemArtifact types.SystemArtifact,
) diff.Measurements {
	result := make(diff.Measurements, 0, len(ms))
	for _, m := range ms {
		result = append(result, measurementForDiffAnalysis(m, filterSystemArtifact))
	}
	return result
}

func measurementForDiffAnalysis(
	m types.MeasuredData,
	filterSystemArtifact types.SystemArtifact,
) diff.Measurement {
	result := diff.Measurement{
		Description: bfformat.NiceString(m.Step),
		Chunks:      make(diff.DataChunks, 0, len(m.References)),
		CustomData:  m,
	}
	for _, ref := range m.References {
		if !types.EqualSystemArtifacts(ref.Artifact, filterSystemArtifact) {
			continue
		}
		result.Chunks = append(result.Chunks, chunksForDiffAnalysis(ref)...)
	}
	return result
}

func chunksForDiffAnalysis(ref types.Reference) diff.DataChunks {
	switch art := ref.Artifact.(type) {
	case types.RawBytes:
		return diff.DataChunks{{
			Description: ref.String(),
			ForceBytes:  art,
			CustomData:  ref,
		}}
	case *biosimage.BIOSImage:
		var chunks diff.DataChunks
		for _, r := range ref.Ranges {
			chunks = append(chunks, diff.DataChunk{
				Description:   ref.String(),
				Reference:     r,
				AddressMapper: biosimage.PhysMemMapper{},
				CustomData:    ref,
			})
		}
		return chunks
	default:
		panic(fmt.Sprintf("supposed to be impossible: %T", art))
	}
}

func outputAnalyzedJSON(
	report diff.AnalysisReport,
	debugInfo map[string]interface{},
	measurements types.MeasuredDataSlice,
) {
	jsonData, err := json.MarshalIndent(struct {
		Report       diff.AnalysisReport
		DebugInfo    map[string]interface{}
		Measurements types.MeasuredDataSlice
	}{report, debugInfo, measurements}, ``, ` `)
	assertNoError(err)
	fmt.Printf("%s", jsonData)
}

func outputJSON(
	diffRanges diff.Ranges,
	debugInfo map[string]interface{},
	measurements types.MeasuredDataSlice,
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
