package main

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"hash"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/bruteforcer"
	"github.com/google/go-tpm/tpm2"
)

func main() {
	// Here we brute-force a TPM measurement against a final PCR0 value.
	//
	// We initially have measurements of two separators, but we need to
	// bruteforce the first measurement to 0x01000001

	// an artificial flow for two separators
	myFlow := types.Flow{
		tpmsteps.InitTPMLazy(0),
		tpmsteps.MeasureSeparator(0),
		tpmsteps.MeasureSeparator(0),
	}

	// the expected final hash (after bruteforcing)
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

	// executing the flow (with two simple "\x00\x00\x00\x00" measurements)
	state := types.NewState()
	state.SetFlow(myFlow, 0)
	state.IncludeTrustChain(tpm.NewTPM())
	process := bootengine.NewBootProcess(state)
	process.Finish()

	// just some debugging
	fmt.Printf("Log:\n%#v\n", process.Log)

	tpmInstance, err := tpm.GetFrom(state)
	if err != nil {
		panic(err)
	}

	// == now let's bruteforce the first measurement ==

	// first find the original (UNHASHED) data of the first measurement
	tpmMeasurements := process.Log.GetDataMeasuredWith(tpmInstance)

	// now let's gather the rest chain (TPM init and the rest TPM Extend-s)
	var (
		tpmLocality *uint8
		tpmExtends  []tpm.CommandExtend
	)
	for _, entry := range tpmInstance.CommandLog {
		switch entry := entry.Command.(type) {
		case tpm.CommandInit:
			tpmLocality = &[]uint8{entry.Locality}[0]
		case tpm.CommandExtend:
			if entry.HashAlgo != tpm2.AlgSHA1 {
				continue
			}
			tpmExtends = append(tpmExtends, entry)
		}
	}
	if tpmLocality == nil {
		panic("the TPMInit command wasn't found")
	}

	// brute force:

	type context struct {
		sha1Hasher hash.Hash
	}
	combination, err := bruteforcer.BruteForce(
		tpmMeasurements[0].Data.ForceBytes, // initialData
		8,                                  // itemSize
		0,                                  // minDistance
		2,                                  // maxDistance
		func() (interface{}, error) { // initFunc
			return &context{
				sha1Hasher: sha1.New(),
			}, nil
		},
		func(_ctx interface{}, data []byte) bool { // checkFunc
			ctx := _ctx.(*context)
			h := ctx.sha1Hasher

			// starting a PCR value from scratch:
			pcrValue := make([]byte, sha1.Size)
			pcrValue[len(pcrValue)-1] = *tpmLocality

			// hashing the bruteforced value before extending
			h.Write(data)
			dataHashed := h.Sum(nil)
			h.Reset()

			// extending it
			pcrValue = extend(h, pcrValue, dataHashed)

			// extending the rest of the measurements (they are already pre-hashed)
			for _, tpmExtend := range tpmExtends[1:] {
				pcrValue = extend(h, pcrValue, tpmExtend.Digest)
			}

			// is it OK?
			return bytes.Equal(pcrValue, expectedHash)
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
	fmt.Printf("COMBINATION: %#v\n", combination)
	fmt.Printf("RESULT: 0x%X\n", result)

	tpmMeasurements[0].Data.ForceBytes = result
	fmt.Printf("resulting measurements: %#v\n", tpmMeasurements)
}
