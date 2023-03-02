package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/pprof"

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
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func main() {
	cbnt.StrictOrderCheck = false
	uefi.DisableDecompression = false
	var regs helpers.FlagRegisters
	// parsing arguments
	flag.Var(&regs, "registers", "")
	netPprofFlag := flag.String("net-pprof", "", "")
	cpuProfileFlag := flag.String("cpu-profile", "", "")
	flag.Parse()

	ctx := context.Background()

	if *netPprofFlag != "" && *cpuProfileFlag != "" {
		log.Fatalf("options '-net-pprof' and '-cpu-profile' cannot be both used at the same time")
	}
	if *netPprofFlag != "" {
		go func() {
			log.Println(http.ListenAndServe(*netPprofFlag, nil))
		}()
	}
	if *cpuProfileFlag != "" {
		f, err := os.Create(*cpuProfileFlag)
		if err != nil {
			log.Fatalf("could not create the CPU profile file '%s': %v", *cpuProfileFlag, err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatalf("could not start the CPU profiling: %v", err)
		}
		defer pprof.StopCPUProfile()
	}

	biosFirmwarePath := flag.Arg(0)
	biosFirmware, err := os.ReadFile(biosFirmwarePath)
	if err != nil {
		panic(fmt.Errorf("unable to read BIOS firmware image '%s': %w", biosFirmwarePath, err))
	}
	biosArtifact := biosimage.New(biosFirmware)

	// the main part
	state := types.NewState()
	state.IncludeSubSystem(tpm.NewTPM())
	state.IncludeSubSystem(intelpch.NewPCH())
	state.IncludeSubSystem(amdpsp.NewPSP())
	state.IncludeSystemArtifact(biosArtifact)
	state.IncludeSystemArtifact(txtpublic.New(registers.Registers(regs)))
	state.IncludeSystemArtifact(amdregisters.New(registers.Registers(regs)))
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
