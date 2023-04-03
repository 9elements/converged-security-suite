package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/amdpsp"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/amdregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/google/go-tpm/tpm2"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func main() {
	cbnt.StrictOrderCheck = false
	uefi.DisableDecompression = false
	var regs helpers.FlagRegisters
	logLevel := logger.LevelWarning
	// parsing arguments
	flag.Var(&regs, "registers", "")
	flag.Var(&logLevel, "log-level", "")
	printMeasuredBytesLimitFlag := flag.Uint("print-measured-bytes-limit", 0, "")
	flag.Parse()
	biosFirmwarePath := flag.Arg(0)
	biosFirmware, err := os.ReadFile(biosFirmwarePath)
	if err != nil {
		panic(fmt.Errorf("unable to read BIOS firmware image '%s': %w", biosFirmwarePath, err))
	}

	ctx := logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logLevel))
	calcAndPrintPCR0(ctx, biosFirmware, registers.Registers(regs), *printMeasuredBytesLimitFlag)
}

func calcAndPrintPCR0(
	ctx context.Context,
	biosFirmware []byte,
	regs registers.Registers,
	printMeasuredBytesLimit uint,
) {
	// the main part
	state := types.NewState()
	state.IncludeSubSystem(tpm.NewTPM())
	state.IncludeSubSystem(intelpch.NewPCH())
	state.IncludeSubSystem(amdpsp.NewPSP())
	state.IncludeSystemArtifact(biosimage.New(biosFirmware))
	state.IncludeSystemArtifact(txtpublic.New(registers.Registers(regs)))
	state.IncludeSystemArtifact(amdregisters.New(registers.Registers(regs)))
	state.SetFlow(flows.Root)
	process := bootengine.NewBootProcess(state)
	process.Finish(ctx)

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
		if printMeasuredBytesLimit > 0 {
			refs := make(types.References, len(measuredData.References()))
			copy(refs, measuredData.References())
			err := refs.Resolve()
			if err != nil {
				panic(err)
			}
			buf := make([]byte, printMeasuredBytesLimit)
			for _, ref := range refs {
				for _, r := range ref.Ranges {
					printBuf := buf
					if r.Length < uint64(printMeasuredBytesLimit) {
						printBuf = printBuf[:r.Length]
					}
					_, err := ref.Artifact.ReadAt(printBuf, int64(r.Offset))
					if err != nil {
						panic(err)
					}
					fmt.Printf("\t\t%X\n", printBuf)
				}
			}
		}
	}

	fmt.Printf("\nTPM EventLog:\n")
	for idx, entry := range tpmInstance.EventLog {
		fmt.Printf("\t%d: %v\n", idx, entry)
	}

	fmt.Printf("\nFinal PCR values:\n")
	for pcrID, values := range tpmInstance.PCRValues {
		fmt.Printf("\tPCR[%d]: SHA1:%X SHA256:%X\n", pcrID, values[tpm2.AlgSHA1], values[tpm2.AlgSHA256])
	}
}
