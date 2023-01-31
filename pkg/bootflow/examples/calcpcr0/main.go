package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/google/go-tpm/tpm2"
	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest"
)

func main() {
	manifest.StrictOrderCheck = false
	var regs helpers.FlagRegisters
	// parsing arguments
	flag.Var(&regs, "registers", "")
	flag.Parse()
	biosFirmwarePath := flag.Arg(0)
	biosFirmware, err := os.ReadFile(biosFirmwarePath)
	if err != nil {
		panic(fmt.Errorf("unable to read BIOS firmware image '%s': %w", biosFirmwarePath, err))
	}

	// the main part
	state := types.NewState(nil)
	state.IncludeSubSystem(tpm.NewTPM())
	state.IncludeSystemArtifact(biosimage.New(biosFirmware))
	state.IncludeSystemArtifact(txtregisters.New(registers.Registers(regs)))
	state.SetFlow(flows.Root)
	process := bootengine.NewBootProcess(state)
	process.Finish(context.Background())

	// printing results
	fmt.Printf("Log:\n%s\n", process.Log)
	tpmInstance, err := tpm.GetFrom(state)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nExecuted TPM commands log:\n")
	for idx, entry := range tpmInstance.CommandLog {
		fmt.Printf("\t%d: %v\n", idx, entry)
	}
	fmt.Printf("\nMeasured/protected data log:\n")
	for idx, measuredData := range state.MeasuredData {
		fmt.Printf("\t%d: %v\n", idx, measuredData)
	}
	fmt.Printf("\nTPM EventLog:\n")
	for idx, entry := range tpmInstance.EventLog {
		fmt.Printf("\t%d: %v\n", idx, entry)
	}
	fmt.Printf("\nFinal PCR values:\n")
	for pcrID, values := range tpmInstance.PCRValues {
		fmt.Printf("\tPCR[%d]: SHA1:%X\n", pcrID, values[tpm2.AlgSHA1])
	}
}
