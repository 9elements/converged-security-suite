package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/amdpsp"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcrbruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/amdregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
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
	compareWithEventLogFlag := flag.String("compare-with-eventlog", "", "")
	expectedPCR0Flag := flag.String("expected-pcr0", "", "")
	printMeasuredBytesLimitFlag := flag.Uint("print-measured-bytes-limit", 0, "")
	flag.Parse()
	biosFirmwarePath := flag.Arg(0)
	biosFirmware, err := os.ReadFile(biosFirmwarePath)
	if err != nil {
		panic(fmt.Errorf("unable to read BIOS firmware image '%s': %w", biosFirmwarePath, err))
	}

	ctx := logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logLevel))
	process := boot(ctx, biosFirmware, registers.Registers(regs))
	printBootResults(ctx, process, *printMeasuredBytesLimitFlag)

	if *compareWithEventLogFlag != "" {
		eventLogFile, err := os.Open(*compareWithEventLogFlag)
		if err != nil {
			panic(err)
		}
		defer eventLogFile.Close()

		eventLog, err := tpmeventlog.Parse(eventLogFile)
		if err != nil {
			panic(err)
		}

		success, _, issues, err := pcrbruteforcer.ReproduceEventLog(ctx, process, eventLog, tpm2.AlgSHA256, pcrbruteforcer.DefaultSettingsReproduceEventLog())
		if err != nil {
			panic(err)
		}
		printEventLogIssues(ctx, issues)
		if !success {
			fmt.Println("unable to reproduce TPM EventLog")
		}
	}

	if *expectedPCR0Flag != "" {
		expectedPCR0, err := hex.DecodeString(*expectedPCR0Flag)
		if err != nil {
			panic(err)
		}

		tpmInstance, err := tpm.GetFrom(process.CurrentState)
		if err != nil {
			panic(err)
		}

		result, err := pcrbruteforcer.ReproduceExpectedPCR0(ctx, tpmInstance.CommandLog, tpm2.AlgSHA256, expectedPCR0, pcrbruteforcer.DefaultSettingsReproducePCR0())
		if err != nil {
			panic(err)
		}

		printReproducePCR0Result(ctx, result)
	}
}

func boot(
	ctx context.Context,
	biosFirmware []byte,
	regs registers.Registers,
) *bootengine.BootProcess {
	// the main part
	state := types.NewState()
	state.IncludeSubSystem(tpm.NewTPM())
	state.IncludeSubSystem(intelpch.NewPCH())
	state.IncludeSubSystem(amdpsp.NewPSP())
	state.IncludeSystemArtifact(biosimage.New(biosFirmware))
	state.IncludeSystemArtifact(txtpublic.New(registers.Registers(regs)))
	state.IncludeSystemArtifact(amdregisters.New(registers.Registers(regs)))
	state.SetFlow(flows.AMD)
	process := bootengine.NewBootProcess(state)
	process.Finish(ctx)
	return process
}

func printBootResults(
	ctx context.Context,
	process *bootengine.BootProcess,
	printMeasuredBytesLimit uint,
) {
	state := process.CurrentState

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
		fmt.Printf("\tPCR[%d]: SHA1:%s SHA256:%s\n", pcrID, values[tpm2.AlgSHA1], values[tpm2.AlgSHA256])
	}
}

func printEventLogIssues(ctx context.Context, issues []pcrbruteforcer.Issue) {
	if len(issues) == 0 {
		return
	}
	fmt.Printf("\nTPM EventLog replay issues:\n")
	for idx, issue := range issues {
		fmt.Printf("\t%3d.) %v\n", idx+1, issue)
	}
}

func printReproducePCR0Result(ctx context.Context, result *pcrbruteforcer.ReproducePCR0Result) {
	if result == nil {
		fmt.Println("unable to reproduce PCR0")
		return
	}
	fmt.Printf("\nReproduce PCR0 result:\n")
	fmt.Printf("\tLocality: %d\n", result.Locality)
	fmt.Printf("\tCorrectedACMPolicyStatus: %#+v\n", result.CorrectACMPolicyStatus)
	if len(result.DisabledMeasurements) == 0 {
		return
	}
	fmt.Printf("\tDisabledMeasurements:\n")
	for idx, disabledMeasurement := range result.DisabledMeasurements {
		fmt.Printf("\t\t%3d.) %v\n", idx+1, disabledMeasurement)
	}
}
