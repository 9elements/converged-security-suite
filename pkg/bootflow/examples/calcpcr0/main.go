package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
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
	netPprofFlag := flag.String("net-pprof", "", "")
	compareWithEventLogFlag := flag.String("compare-with-eventlog", "", "")
	expectedPCR0Flag := flag.String("expected-pcr0", "", "")
	printMeasuredBytesLimitFlag := flag.Uint("print-measured-bytes-limit", 0, "")
	flag.Parse()
	ctx := logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logLevel))

	if *netPprofFlag != "" {
		go func() {
			logger.Error(ctx, http.ListenAndServe(*netPprofFlag, nil))
		}()
	}

	biosFirmwarePath := flag.Arg(0)
	biosFirmware, err := os.ReadFile(biosFirmwarePath)
	if err != nil {
		panic(fmt.Errorf("unable to read BIOS firmware image '%s': %w", biosFirmwarePath, err))
	}

	process := boot(ctx, biosFirmware, registers.Registers(regs))
	printBootResults(ctx, process, *printMeasuredBytesLimitFlag)

	tpmInstance, err := tpm.GetFrom(process.CurrentState)
	if err != nil {
		panic(err)
	}

	var reproducePCR0Result *pcrbruteforcer.ReproducePCR0Result
	commandLog := tpmInstance.CommandLog
	if *expectedPCR0Flag != "" {
		expectedPCR0, err := hex.DecodeString(*expectedPCR0Flag)
		if err != nil {
			panic(err)
		}

		reproducePCR0Result, err = pcrbruteforcer.ReproduceExpectedPCR0(ctx, commandLog, tpm2.AlgSHA256, expectedPCR0, pcrbruteforcer.DefaultSettingsReproducePCR0())
		if err != nil {
			panic(err)
		}

		printReproducePCR0Result(ctx, expectedPCR0, commandLog, reproducePCR0Result, tpm2.AlgSHA256, registers.Registers(regs))
	}

	var combinedCommandLog tpm.CommandLog
	if *compareWithEventLogFlag != "" {
		eventLogFile, err := os.Open(*compareWithEventLogFlag)
		if err != nil {
			panic(err)
		}
		defer eventLogFile.Close()

		parsedEventLog, err := tpmeventlog.Parse(eventLogFile)
		if err != nil {
			panic(err)
		}

		result, _, issues, err := pcrbruteforcer.ReproduceEventLog(ctx, process, parsedEventLog, tpm2.AlgSHA256, pcrbruteforcer.DefaultSettingsReproduceEventLog())
		if err != nil {
			panic(err)
		}
		printEventLogIssues(ctx, issues)

		eventLog := tpm.EventLogFromParsed(parsedEventLog)
		commands := eventLog.RestoreCommands()
		commandLog = commandLog[:0]
		for _, cmd := range commands {
			commandLog = append(commandLog, tpm.CommandLogEntry{
				Command: cmd,
			})
		}
		combinedCommandLog = result.CombineAsRestoredCommandLog()
	}

	expectedPCR0, err := hex.DecodeString(*expectedPCR0Flag)
	if err != nil {
		panic(err)
	}

	if reproducePCR0Result != nil || *expectedPCR0Flag == "" {
		return
	}

	for _, commandLog := range []tpm.CommandLog{
		commandLog,
		sanitizeCommandLog(commandLog),
		combinedCommandLog,
		sanitizeCommandLog(combinedCommandLog),
	} {
		logger.Debugf(ctx, "ReproducePCR0: CommandLog = %s", format.NiceStringWithIntend(commandLog))

		for _, maxReorders := range []int{0, 1, 2, 3} {
			settings := pcrbruteforcer.DefaultSettingsReproducePCR0()
			settings.MaxDisabledMeasurements = 6 - maxReorders*2
			settings.MaxReorders = maxReorders

			logger.Debugf(ctx, "ReproducePCR0Settings = %#+v", settings)

			reproducePCR0Result, err = pcrbruteforcer.ReproduceExpectedPCR0(ctx, commandLog, tpm2.AlgSHA256, expectedPCR0, settings)
			if err != nil {
				panic(err)
			}

			printReproducePCR0Result(ctx, expectedPCR0, commandLog, reproducePCR0Result, tpm2.AlgSHA256, registers.Registers(regs))
			if reproducePCR0Result != nil {
				return
			}
		}
	}

	fmt.Println("unable to reproduce PCR0")
}

func sanitizeCommandLog(commandLog tpm.CommandLog) tpm.CommandLog {
	commandLogSanitized := make(tpm.CommandLog, 0, len(commandLog))
	isInitialized := false
	digestDenyList := map[string]struct{}{}
	for _, logEntry := range commandLog {
		switch cmd := logEntry.Command.(type) {
		case *tpm.CommandInit:
			if isInitialized {
				continue
			}
			isInitialized = true
			commandLogSanitized = append(commandLogSanitized, logEntry)
		case *tpm.CommandEventLogAdd:
			if strings.HasPrefix(strings.ToLower(string(cmd.Data)), "hrot measurement") {
				commandLogSanitized = append(commandLogSanitized, tpm.CommandLogEntry{
					Command:          &cmd.CommandExtend,
					CauseCoordinates: logEntry.CauseCoordinates,
					CauseAction:      logEntry.CauseAction,
				})
				digestDenyList[string(cmd.Digest)] = struct{}{}
			}
		}
	}
	for _, logEntry := range commandLog {
		switch cmd := logEntry.Command.(type) {
		case *tpm.CommandExtend:
			if _, ok := digestDenyList[string(cmd.Digest)]; ok {
				continue
			}
			allZerosDigest := true
			for _, b := range cmd.Digest {
				if b != 0 {
					allZerosDigest = false
					break
				}
			}
			if allZerosDigest {
				continue
			}
			commandLogSanitized = append(commandLogSanitized, logEntry)
		}
	}

	return commandLogSanitized
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
	state.SetFlow(flows.Root)
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
			refs := make(types.References, len(measuredData.References))
			copy(refs, measuredData.References)
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

func printReproducePCR0Result(
	ctx context.Context,
	expectedPCR0 tpm.Digest,
	commandLog tpm.CommandLog,
	result *pcrbruteforcer.ReproducePCR0Result,
	hashAlgo tpm.Algorithm,
	regs registers.Registers,
) {
	if result == nil {
		return
	}
	fmt.Printf("\nReproduce PCR0 result:\n")
	fmt.Printf("\tLocality: %d\n", result.Locality)
	if result.ACMPolicyStatus != nil && *result.ACMPolicyStatus != regs.Find(registers.AcmPolicyStatusRegisterID) {
		fmt.Printf("\tCorrectedACMPolicyStatus: %016X (given: %016X)\n", *result.ACMPolicyStatus, regs.Find(registers.AcmPolicyStatusRegisterID))
	}

	resultCommandLog := make(tpm.CommandLog, 0, len(commandLog))

	measurementIdx := map[*tpm.CommandLogEntry]int{}
	for idx := range commandLog {
		measurementIdx[&commandLog[idx]] = idx
	}

	if len(result.DisabledMeasurements) != 0 {
		fmt.Printf("\tDisabledMeasurements:\n")
		for _, disabledMeasurement := range result.DisabledMeasurements {
			idx := measurementIdx[disabledMeasurement]
			delete(measurementIdx, disabledMeasurement)
			fmt.Printf("\t\t%3d.) %v\n", idx, disabledMeasurement)
		}
	}
	containsInitCmd := false
	for idx, logEntry := range commandLog {
		if _, ok := measurementIdx[&commandLog[idx]]; !ok {
			continue
		}
		switch cmd := logEntry.Command.(type) {
		case *tpm.CommandEventLogAdd:
			continue
		case *tpm.CommandInit:
			if idx != 0 {
				continue
			}
			if cmd.Locality != result.Locality {
				continue
			}
			containsInitCmd = true
		case *tpm.CommandExtend:
			if cmd.PCRIndex != 0 {
				continue
			}
			if cmd.HashAlgo != hashAlgo {
				continue
			}
		}
		resultCommandLog = append(resultCommandLog, logEntry)
	}

	if len(result.OrderSwaps) != 0 {
		fmt.Printf("\tOrderSwaps:\n")
		for idx, orderSwap := range result.OrderSwaps {
			fmt.Printf("\t\t%3d.) #%d <-> #%d\n", idx+1, orderSwap.IdxA, orderSwap.IdxB)
		}
		pcrbruteforcer.ApplyOrderSwaps(result.OrderSwaps, resultCommandLog)
	}

	fmt.Printf("\tThe instruction to reproduce the PCR0:\n")
	for idx, measurement := range resultCommandLog {
		fmt.Printf("\t\t%3d.) %v\n", idx+1, measurement)
	}

	dummyTPM := tpm.NewTPM()
	if !containsInitCmd {
		err := dummyTPM.TPMInit(ctx, result.Locality, nil)
		if err != nil {
			logger.Error(ctx, err)
			return
		}
	}
	resultCommandLog.Commands().Apply(ctx, dummyTPM)
	replayedPCR0, err := dummyTPM.PCRValues.Get(0, hashAlgo)
	if err != nil {
		logger.Error(ctx, err)
		return
	}
	if !bytes.Equal(replayedPCR0, expectedPCR0) {
		fmt.Printf("\tinternal error: replayed PCR0 does not match the expected one; the information above could not be trusted:\n\t\t%s != %s\n", replayedPCR0, expectedPCR0)
		return
	}
	fmt.Printf("\t\tResulting PCR0: %s\n", replayedPCR0)
}
