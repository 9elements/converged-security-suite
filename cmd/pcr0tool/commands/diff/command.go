package diff

import (
	"context"
	"flag"
	"log"
	_ "net/http/pprof"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
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
	outputFormat *string
	flow         *string
	netPprof     *string
	registers    helpers.FlagRegisters
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
	cmd.outputFormat = flag.String("output-format", "analyzed-text", `Values: "analyzed-text", "analyzed-json", "json"`)
	cmd.flow = flag.String("flow", flows.Root.Name, "values: "+commands.FlowCommandLineValues())
	cmd.netPprof = flag.String("net-pprof", "", `start listening for "net/http/pprof", example value: "127.0.0.1:6060"`)
	flag.Var(&cmd.registers, "registers", "[optional] file that contains registers as a json array (use value '/dev' to use registers of the local machine)")
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, args []string) {
	panic("not implemented, yet")
}

/*
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

	firmwareGood, err := uefi.ParseUEFIFirmwareFile(args[0])
	assertNoError(err)
	firmwareGoodData := firmwareGood.Buf()

	state.IncludeSystemArtifact(biosimage.NewFromParsed(firmwareGood))

	firmwareBadData, err := ostools.FileToBytes(args[1])
	if firmwareBadData == nil {
		assertNoError(err)
	}

	process := bootengine.NewBootProcess(state)
	process.Finish(ctx)

	_ = process.Log.Error()

	measurements, _, debugInfo, err := pcr.GetMeasurements(ctx, firmwareGood, 0, measureOpts...)
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
			diff.Analyze(diffEntries, measurementsForDiffAnalysis(measurements), firmwareGood, firmwareBadData),
			debugInfo, firmwareGoodData, firmwareBadData,
		)
		assertNoError(err)
		fmt.Print(output)
	case outputFormatTypeAnalyzedJSON:
		outputAnalyzedJSON(
			diff.Analyze(diffEntries, measurementsForDiffAnalysis(measurements), firmwareGood, firmwareBadData),
			debugInfo, measurements,
		)
	case outputFormatTypeJSON:
		outputJSON(diffEntries, debugInfo, measurements)
	}
}

func measurementsForDiffAnalysis(ms pcr.Measurements) diff.Measurements {
	result := make(diff.Measurements, 0, len(ms))
	for _, m := range ms {
		result = append(result, measurementForDiffAnalysis(m))
	}
	return result
}

func measurementForDiffAnalysis(m *pcr.Measurement) diff.Measurement {
	result := diff.Measurement{
		Description: m.ID.String(),
		Chunks:      make(diff.DataChunks, 0, len(m.Data)),
		CustomData:  m,
	}
	for _, chunk := range m.Data {
		result.Chunks = append(result.Chunks, chunkForDiffAnalysis(chunk))
	}
	return result
}

func chunkForDiffAnalysis(chunk pcr.DataChunk) diff.DataChunk {
	return diff.DataChunk{
		Description: chunk.String(),
		ForceBytes:  chunk.ForceData,
		Reference:   chunk.Range,
		CustomData:  chunk,
	}
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
*/
