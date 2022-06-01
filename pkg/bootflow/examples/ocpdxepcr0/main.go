package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosfirmware"
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
	state.SetFlow(flows.OCPDXE(), 0)
	state.EnableTrustChain(tpm.NewTPM())
	state.EnableSystemArtifact(biosfirmware.NewBIOSFirmware(biosFirmware))
	process := bootengine.NewBootProcess(state)
	process.Finish()

	// printing results
	tpm.StateExec(state, func(t *tpm.TPM) error {
		fmt.Printf("PCR values:\n")
		for pcrID, values := range t.PCRValues {
			fmt.Printf("\tPCR[%d]: SHA1:%X\n", pcrID, values[tpm2.AlgSHA1])
		}
		fmt.Printf("TPM EventLog:\n")
		for idx, entry := range t.EventLog {
			if entry.HashAlgo != tpm2.AlgSHA1 {
				continue
			}
			fmt.Printf("\t%d: %#v\n", idx, entry)
		}
		fmt.Printf("TPM commands log:\n")
		for idx, entry := range t.CommandLog {
			if entry, ok := entry.(tpm.CommandLogEntryExtend); ok {
				if entry.HashAlgo != tpm2.AlgSHA1 {
					continue
				}
			}
			fmt.Printf("\t%d: %#v\n", idx, entry)
		}
		return nil
	})
}
