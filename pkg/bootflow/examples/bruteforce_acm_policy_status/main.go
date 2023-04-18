package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"hash"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/bruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/google/go-tpm/tpm2"
)

func main() {
	// Here we brute-force a TPM measurement against a final PCR0 value.
	//
	// We initially have measurements of two separators, but we need to
	// bruteforce the first measurement to 0x01000001

	// an artificial flow for two separators
	myFlow := types.NewFlow("example-flow", types.Steps{
		tpmsteps.InitTPM(0, false),
		tpmsteps.Measure(0, tpmeventlog.EV_SEPARATOR, datasources.Bytes{0, 0, 0, 0}),
		tpmsteps.Measure(0, tpmeventlog.EV_SEPARATOR, datasources.Bytes{0, 0, 0, 0}),
	})

	// executing the flow (with two simple "\x00\x00\x00\x00" measurements)
	state := types.NewState()
	state.SetFlow(myFlow)
	state.IncludeSubSystem(tpm.NewTPM())
	process := bootengine.NewBootProcess(state)
	process.Finish(context.Background())

	// just some debugging
	fmt.Printf("Log:\n%v", process.Log)

	tpmInstance, err := tpm.GetFrom(state)
	if err != nil {
		panic(err)
	}

	// == now let's bruteforce the first measurement ==

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
	expectedHash := getExpectedHash()
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
	result := []byte("\x00\x00\x00\x00")
	bruteforcer.ApplyBitFlipsBytes(combination, result)
	fmt.Printf("COMBINATION: %v\n", combination)
	fmt.Printf("RESULT: 0x%X\n", result)

	tpmMeasurements := process.Log.GetDataMeasuredWith(tpmInstance)
	bruteforcer.ApplyBitFlipsBytes(combination, tpmMeasurements[0].Data.ForcedBytes())
	fmt.Printf("resulting measurements:\n%v", tpmMeasurements)
}

// getExpectedHash returns the expected final hash (after bruteforcing)
func getExpectedHash() []byte {
	expectedHash := make([]byte, sha1.Size)
	extend := func(h hash.Hash, a, b []byte) []byte {
		defer h.Reset()
		h.Write(a)
		h.Write(b)
		return h.Sum(nil)
	}
	sep0, sep1 := sha1.Sum([]byte("\x01\x00\x00\x01")), sha1.Sum([]byte("\x00\x00\x00\x00"))
	expectedHash = extend(sha1.New(), expectedHash, sep0[:])
	expectedHash = extend(sha1.New(), expectedHash, sep1[:])
	return expectedHash
}
