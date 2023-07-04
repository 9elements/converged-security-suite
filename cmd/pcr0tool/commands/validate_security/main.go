package validatesecurity

import (
	"context"
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine/validator"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/amdpsp"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/amdregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	registers                  helpers.FlagRegisters
	injectBenignCorruptionFlag *string
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	flag.Var(&cmd.registers, "registers", "[optional] file that contains registers as a json array (use value '/dev' to use registers of the local machine)")
	cmd.injectBenignCorruptionFlag = flag.String("inject-benign-corruption", "", "output file")
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<firmware>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "executes available security validators against the provided firmware image"
}

func usageAndExit() {
	flag.Usage()
	os.Exit(2)
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, args []string) {
	if len(args) != 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "expected amount of arguments is one, but received: %d\n", len(args))
		usageAndExit()
	}

	flag.Parse()

	biosFirmwarePath := flag.Arg(0)
	biosFirmware, err := os.ReadFile(biosFirmwarePath)
	if err != nil {
		panic(fmt.Errorf("unable to read BIOS firmware image '%s': %w", biosFirmwarePath, err))
	}
	biosArtifact := biosimage.New(biosFirmware)

	state := types.NewState()
	state.IncludeSubSystem(tpm.NewTPM())
	state.IncludeSubSystem(intelpch.NewPCH())
	state.IncludeSubSystem(amdpsp.NewPSP())
	state.IncludeSystemArtifact(biosArtifact)
	state.IncludeSystemArtifact(txtpublic.New(registers.Registers(cmd.registers)))
	state.IncludeSystemArtifact(amdregisters.New(registers.Registers(cmd.registers)))
	state.SetFlow(flows.Root)
	process := bootengine.NewBootProcess(state)
	process.Finish(context.Background())

	fmt.Printf("\nActors:\n")
	var prevActor types.Actor
	for _, step := range process.Log {
		if step.Actor == prevActor {
			continue
		}
		prevActor = step.Actor

		fmt.Printf("\t* %s: %s\n", format.NiceString(step.Actor), format.NiceString(step.ActorCode))
	}

	fmt.Printf("\nMeasured/protected data log:\n")
	for idx, measuredData := range state.MeasuredData {
		fmt.Printf("\t%d: %s\n", idx, measuredData)
	}

	fmt.Printf("\nMeasured/protected data:\n")
	measuredRefs := state.MeasuredData.References()
	measuredRefs.SortAndMerge()
	for idx, ref := range measuredRefs {
		fmt.Printf("\t%d: %T", idx, ref.Artifact)
		if ref.AddressMapper != nil {
			fmt.Printf(" (%T)", ref.AddressMapper)
		}
		fmt.Printf("\n")
		for rIdx, r := range ref.Ranges {
			fmt.Printf("\t\t%d: 0x%X:0x%X\n", rIdx, r.Offset, r.End())
		}
	}

	issuesCount := 0
	fmt.Printf("\nIssues:\n")
	for _, v := range validator.All() {
		issues := v.Validate(ctx, state, process.Log)
		if _, ok := v.(validator.ValidatorFinalCoverageIsComplete); ok && *cmd.injectBenignCorruptionFlag != "" {
			if err := injectBenignCorruption(*cmd.injectBenignCorruptionFlag, biosArtifact, issues); err != nil {
				panic(fmt.Errorf("unable to inject a benign corruption: %w", err))
			}
		}
		if len(issues) == 0 {
			continue
		}
		issuesCount += len(issues)
		fmt.Printf("\t%s:\n", format.NiceString(v))
		for idx, issue := range issues {
			fmt.Printf("\t\t%d. %v; step: %v\n", idx+1, format.NiceString(issue), format.NiceString(process.Log[issue.StepIdx].Step))
		}
	}
	if issuesCount == 0 {
		fmt.Printf("\t<NONE>\n")
	}
}
