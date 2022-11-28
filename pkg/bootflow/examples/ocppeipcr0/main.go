package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/google/go-tpm/tpm2"
)

func main() {
	// parsing arguments
	flag.Parse()
	biosFirmwarePath := flag.Arg(0)
	biosFirmware, err := os.ReadFile(biosFirmwarePath)
	if err != nil {
		panic(fmt.Errorf("unable to read BIOS firmware image '%s': %w", biosFirmwarePath, err))
	}

	// the main part
	state := types.NewState()
	state.IncludeTrustChain(tpm.NewTPM())
	state.IncludeSystemArtifact(biosimage.New(biosFirmware))
	state.SetFlow(flows.OCPPEI())
	process := bootengine.NewBootProcess(state)
	process.Finish(context.Background())

	// printing results
	tpmInstance, err := tpm.GetFrom(state)
	if err != nil {
		panic(err)
	}
	fmt.Printf("PCR values:\n")
	for pcrID, values := range tpmInstance.PCRValues {
		fmt.Printf("\tPCR[%d]: SHA1:%X\n", pcrID, values[tpm2.AlgSHA1])
	}
	fmt.Printf("TPM EventLog:\n")
	for idx, entry := range tpmInstance.EventLog {
		if entry.HashAlgo != tpm2.AlgSHA1 {
			continue
		}
		fmt.Printf("\t%d: %#v\n", idx, entry)
	}
	fmt.Printf("TPM commands log:\n")
	for idx, entry := range tpmInstance.CommandLog {
		if entry, ok := entry.Command.(*tpm.CommandExtend); ok {
			if entry.HashAlgo != tpm2.AlgSHA1 {
				continue
			}
		}
		fmt.Printf("\t%d: %#v\n", idx, entry)
	}
	fmt.Printf("Measured Data log:\n")
	for idx, measuredData := range state.MeasuredData {
		fmt.Printf("\t%d: %#v\n", idx, measuredData)
	}
}
