package pcrbruteforcer

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/testdata/firmware"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

type fataler interface {
	Fatal(args ...interface{})
}

func TestReproduceExpectedPCR0(t *testing.T) {
	ctx := logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logger.LevelTrace))

	const correctACMRegValue = 0x0000000200108681

	pcr0Correct := unhex(t, "63426C1F8C0DB32CC3EA9BB4391CD6D0C6B87198")

	// Take PCR0 with partially enabled measurements, only:
	// * PCR0_DATA
	// * DXE
	// Thus without:
	// * PCD Firmware Vendor Version
	// * Separator
	pcr0Incomplete := unhex(t, "4CB03F39E94B0AB4AD99F9A54E3FD0DEFB0BB2D4")
	pcr0Invalid := unhex(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	// Swapped PCR0_DATA with Separator and DXE with PCD Firmware Vendor Version
	pcr0ReorderedContributions := unhex(t, "8B6F10F7D4425BACB22ADF41176AFA546036FC72")

	testACM := func(t *testing.T, pcr0 []byte, acmReg uint64) {
		tpmInstance := tpm.NewTPM()
		biosFW := biosimage.New(firmware.FakeIntelFirmware)
		state := types.NewState()
		state.IncludeSubSystem(tpmInstance)
		state.IncludeSubSystem(intelpch.NewPCH())
		state.IncludeSystemArtifact(biosFW)
		state.IncludeSystemArtifact(&txtpublic.TXTPublic{
			Registers: registers.Registers{registers.ParseACMPolicyStatusRegister(acmReg)},
		})
		state.SetFlow(testFlow)
		process := bootengine.NewBootProcess(state)
		process.Finish(ctx)

		settings := DefaultSettingsReproducePCR0()
		settings.EnableACMPolicyCombinatorialStrategy = true
		if bytes.Equal(pcr0, pcr0ReorderedContributions) {
			settings.MaxReorders = 2
		}

		result, err := ReproduceExpectedPCR0(
			ctx,
			tpmInstance.CommandLog,
			tpm2.AlgSHA1,
			pcr0,
			settings,
		)
		require.Nil(t, err)

		if bytes.Equal(pcr0, pcr0Invalid) {
			require.Nil(t, result)
		} else {
			require.NotNil(t, result, "%v", err)
			require.NotNil(t, result.CorrectACMPolicyStatus)
			require.Equal(t, uint64(correctACMRegValue), result.CorrectACMPolicyStatus.Raw())
		}
	}

	t.Run("test_uncorrupted", func(t *testing.T) { testACM(t, pcr0Correct, correctACMRegValue) })
	t.Run("test_corrupted_linear_easy", func(t *testing.T) { testACM(t, pcr0Correct, correctACMRegValue+0x1) })
	t.Run("test_corrupted_linear", func(t *testing.T) { testACM(t, pcr0Correct, correctACMRegValue+0x1c) })
	t.Run("test_corrupted_combinatorial", func(t *testing.T) { testACM(t, pcr0Correct, correctACMRegValue^0x10000000) })
	t.Run("test_incompletePCR0_corruptedACM", func(t *testing.T) { testACM(t, pcr0Incomplete, correctACMRegValue+1) })
	t.Run("test_invalid_PCR0", func(t *testing.T) { testACM(t, pcr0Invalid, correctACMRegValue) })
	t.Run("test_reordered_contributions_PCR0", func(t *testing.T) { testACM(t, pcr0ReorderedContributions, correctACMRegValue) })
	t.Run("test_reordered_contributions_PCR0_corruptedACM", func(t *testing.T) { testACM(t, pcr0ReorderedContributions, correctACMRegValue+1) })
}

func BenchmarkReproduceExpectedPCR0(b *testing.B) {
	ctx := context.Background()

	tpmInstance := tpm.NewTPM()
	biosFW := biosimage.New(firmware.FakeIntelFirmware)
	state := types.NewState()
	state.IncludeSubSystem(tpmInstance)
	state.IncludeSubSystem(intelpch.NewPCH())
	state.IncludeSystemArtifact(biosFW)
	state.SetFlow(testFlow)
	process := bootengine.NewBootProcess(state)
	process.Finish(ctx)

	//const correctACMRegValue = 0x0000000200108681

	pcr0Correct := unhex(b, "F4D6D480F066F64A78598D82D1DEC77BBD53DEC1")
	pcr0Incomplete := unhex(b, "4CB03F39E94B0AB4AD99F9A54E3FD0DEFB0BB2D4")
	pcr0Invalid := unhex(b, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	settings := DefaultSettingsReproducePCR0()
	settings.EnableACMPolicyCombinatorialStrategy = true

	acmCorruptions := []uint64{
		0x100000000, 0x100100000, 0x1c, 0,
	}

	for _, acmCorruption := range acmCorruptions {
		b.Run(fmt.Sprintf("acmCorruption_%X", acmCorruption), func(b *testing.B) {
			b.Run("correctPCR0", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, err := ReproduceExpectedPCR0(
						ctx,
						tpmInstance.CommandLog,
						tpm2.AlgSHA1,
						pcr0Correct,
						settings,
					)
					if err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("incompletePCR0", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, err := ReproduceExpectedPCR0(
						ctx,
						tpmInstance.CommandLog,
						tpm2.AlgSHA1,
						pcr0Incomplete,
						settings,
					)
					if err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("invalidPCR0", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, err := ReproduceExpectedPCR0(
						ctx,
						tpmInstance.CommandLog,
						tpm2.AlgSHA1,
						pcr0Invalid,
						settings,
					)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
