package bruteforceacmpolicystatus

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands"
	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/amdpsp"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/amdregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/bruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/google/go-tpm/tpm2"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	flow             *string
	registers        helpers.FlagRegisters
	expectedPCR0Flag *string
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.flow = flag.String("flow", flows.Root.Name, "values: "+commands.FlowCommandLineValues())
	flag.Var(&cmd.registers, "registers", "[optional] file that contains registers as a json array (use value '/dev' to use registers of the local machine)")
	cmd.expectedPCR0Flag = flag.String("expected-pcr0", "", "")
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<firmware>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "[Intel CBnT specific] brute forces the ACM policy status value to get the expected PCR0"
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

	flow, ok := flows.GetFlowByName(*cmd.flow)
	if !ok {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "unknown boot flow: '%s'\n", *cmd.flow)
		usageAndExit()
	}

	firmware, err := uefi.ParseUEFIFirmwareFile(args[0])
	if err != nil {
		panic(err)
	}

	origACMPolicyStatus, ok := registers.FindACMPolicyStatus(registers.Registers(cmd.registers))
	if !ok {
		panic("ACM policy status register is not set")
	}

	state := types.NewState()
	state.SetFlow(flow)
	state.IncludeSubSystem(tpm.NewTPM())
	state.IncludeSubSystem(intelpch.NewPCH())
	state.IncludeSubSystem(amdpsp.NewPSP())
	state.IncludeSystemArtifact(txtpublic.New(registers.Registers(cmd.registers)))
	state.IncludeSystemArtifact(amdregisters.New(registers.Registers(cmd.registers)))
	state.IncludeSystemArtifact(biosimage.NewFromParsed(firmware))
	process := bootengine.NewBootProcess(state)
	process.Finish(context.Background())

	// just some debugging
	fmt.Printf("Log:\n%v", process.Log)

	tpmInstance, err := tpm.GetFrom(state)
	if err != nil {
		panic(err)
	}

	// == now let's bruteforce the PCR0 first measurement ==

	// find the first measurement:

	var (
		firstMeasurementData []byte
		commandIdx           int
	)
	for idx, entry := range tpmInstance.CommandLog {
		cmd, ok := entry.Command.(*tpm.CommandExtend)
		if !ok {
			continue
		}
		if cmd.PCRIndex != 0 {
			continue
		}
		if cmd.HashAlgo != tpm2.AlgSHA1 {
			continue
		}
		step := entry.Step().(types.StaticStep)
		if len(step) != 1 {
			panic(fmt.Errorf("unexpected length: %d (expected: 1)", len(step)))
		}
		firstMeasurementData = step[0].(*tpmactions.TPMEvent).DataSource.(datasources.Bytes)
		commandIdx = idx
		break
	}
	if firstMeasurementData == nil {
		panic("the measurement data was not found")
	}

	// brute force it:
	expectedHash, err := hex.DecodeString(*cmd.expectedPCR0Flag)
	if err != nil {
		panic(err)
	}
	type contextT struct {
		sha1Hasher  hash.Hash
		tpm         *tpm.TPM
		tpmCommands tpm.Commands
	}
	combination, err := bruteforcer.BruteForce(
		firstMeasurementData, // initialData
		8,                    // itemSize
		0,                    // minDistance
		2,                    // maxDistance
		func() (interface{}, error) { // initFunc
			return &contextT{
				sha1Hasher:  sha1.New(),
				tpm:         tpm.NewTPM(),
				tpmCommands: tpmInstance.CommandLog.Commands(),
			}, nil
		},
		func(_ctx interface{}, data []byte) bool { // checkFunc
			ctx := _ctx.(*contextT)

			ctx.sha1Hasher.Reset()
			ctx.sha1Hasher.Write(data)
			newDigest := ctx.sha1Hasher.Sum(nil)

			ctx.tpmCommands[commandIdx].(*tpm.CommandExtend).Digest = newDigest[:]

			ctx.tpm.Reset()
			ctx.tpm.TPMExecute(context.Background(), ctx.tpmCommands, nil)

			// is it OK?
			return bytes.Equal(ctx.tpm.PCRValues[0][tpm2.AlgSHA1], expectedHash)
		},
		bruteforcer.ApplyBitFlipsBytes, // applyBitFlipsFunc
		0,
	)
	if err != nil {
		panic(err)
	}

	// printing the result
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, origACMPolicyStatus.Raw())
	bruteforcer.ApplyBitFlipsBytes(combination, result)
	fmt.Printf("COMBINATION: %v\n", combination)
	fmt.Printf("RESULT: 0x%X\n", result)

	tpmMeasurements := process.Log.GetDataMeasuredWith(tpmInstance)
	bruteforcer.ApplyBitFlipsBytes(combination, tpmMeasurements[0].Data.ForcedBytes())
	fmt.Printf("resulting measurements:\n%v", tpmMeasurements)
}
