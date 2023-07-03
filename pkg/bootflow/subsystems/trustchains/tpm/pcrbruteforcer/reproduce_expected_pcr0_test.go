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
	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/pkg/field"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

type fataler interface {
	Fatal(args ...interface{})
}

func TestReproduceExpectedPCR0(t *testing.T) {
	ctx := logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logger.LevelDebug))
	enabledSlowTracing = false

	const correctACMRegValue = 0x0000000200108681

	// $ go install github.com/xaionaro-go/replaypcr0@latest && replaypcr0 -locality 3 /tmp/list
	// using locality 3
	// <- 527C9A38B2F45FBF89C382547E0A0812722A47D3: A4CAA688536EFDE1192C892758CA4FD75AC163A4
	// <- C42FEDAD268200CB1D15F97841C344E79DAE3320: 3F1BFF5FE9E36CF8450E6F231DB8D2BDB617C476
	// <- 4C9836F73CC42ADBECE7D565B783E618B4A75C22: DBD3F773F3685E9C5462FD9C53833593E4B98079
	// <- 9069CA78E7450A285173431B3E52C5C25299E473: 63426C1F8C0DB32CC3EA9BB4391CD6D0C6B87198
	// result digest is: 63426C1F8C0DB32CC3EA9BB4391CD6D0C6B87198
	pcr0Correct := unhex(t, "63426C1F8C0DB32CC3EA9BB4391CD6D0C6B87198")

	// Take PCR0 with partially enabled measurements, only:
	// * PCR0_DATA
	// * DXE
	// Thus without:
	// * PCD Firmware Vendor Version
	// * Separator
	//
	// $ replaypcr0 -locality 3 /tmp/list
	// using locality 3
	// <- 527C9A38B2F45FBF89C382547E0A0812722A47D3: A4CAA688536EFDE1192C892758CA4FD75AC163A4
	// <- 4C9836F73CC42ADBECE7D565B783E618B4A75C22: 4CB03F39E94B0AB4AD99F9A54E3FD0DEFB0BB2D4
	// result digest is: 4CB03F39E94B0AB4AD99F9A54E3FD0DEFB0BB2D4
	pcr0Incomplete := unhex(t, "4CB03F39E94B0AB4AD99F9A54E3FD0DEFB0BB2D4")

	// just an invalid (practically impossible) value:
	pcr0Invalid := unhex(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	// Swapped PCR0_DATA with Separator and DXE with PCD Firmware Vendor Version
	//
	// $ replaypcr0 -locality 3 /tmp/list
	// using locality 3
	// <- 9069CA78E7450A285173431B3E52C5C25299E473: 3CBCD420D8A58DE607677E036109F6EB2C72EF7F
	// <- 4C9836F73CC42ADBECE7D565B783E618B4A75C22: ECABB304F3041B86DE02D27CCD12F6DB17F0FECE
	// <- C42FEDAD268200CB1D15F97841C344E79DAE3320: 1C677A2314BB4723BD5B74F6D92911BCFEA2FB7A
	// <- 527C9A38B2F45FBF89C382547E0A0812722A47D3: 8B6F10F7D4425BACB22ADF41176AFA546036FC72
	// result digest is: 8B6F10F7D4425BACB22ADF41176AFA546036FC72
	pcr0ReorderedContributions := unhex(t, "8B6F10F7D4425BACB22ADF41176AFA546036FC72")

	testACM := func(t *testing.T, pcr0 []byte, acmReg uint64) {
		ctx := belt.WithFields(ctx, field.Map[any]{
			"test_name":     t.Name(),
			"expected_pcr0": fmt.Sprintf("%X", pcr0),
			"acm_reg":       fmt.Sprintf("%X", acmReg),
		})
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
		require.NoError(t, process.Log.Error())

		logger.Debugf(ctx, "%s", tpmInstance.CommandLog)

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
			return
		}

		require.NotNil(t, result)
		if acmReg == correctACMRegValue {
			return
		}

		require.NotNil(t, result.ACMPolicyStatus)
		require.Equal(t, uint64(correctACMRegValue), result.ACMPolicyStatus.Raw())
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
