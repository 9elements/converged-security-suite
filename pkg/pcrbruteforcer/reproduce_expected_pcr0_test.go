package pcrbruteforcer

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/9elements/converged-security-suite/v2/testdata/firmware"
	"github.com/linuxboot/contest/pkg/xcontext/bundles/logrusctx"
	"github.com/linuxboot/contest/pkg/xcontext/logger"

	"github.com/google/go-tpm/tpm2"
	"github.com/linuxboot/contest/pkg/xcontext"
	"github.com/stretchr/testify/require"
)

type fataler interface {
	Fatal(args ...interface{})
}

func getFirmware(fataler fataler) *uefi.UEFI {
	firmwareImage := firmware.FakeIntelFirmware

	firmware, err := uefi.ParseUEFIFirmwareBytes(firmwareImage)
	if err != nil {
		fataler.Fatal(err)
	}

	return firmware
}

func TestReproduceExpectedPCR0(t *testing.T) {
	firmware := getFirmware(t)

	const correctACMRegValue = 0x0000000200108681

	pcr0Correct := unhex(t, "F4D6D480F066F64A78598D82D1DEC77BBD53DEC1")

	// Take PCR0 with partially enabled measurements, only:
	// * PCR0_DATA
	// * DXE
	// Thus without:
	// * PCD Firmware Vendor Version
	// * Separator
	pcr0Incomplete := unhex(t, "4CB03F39E94B0AB4AD99F9A54E3FD0DEFB0BB2D4")

	pcr0Invalid := unhex(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	testACM := func(t *testing.T, pcr0 []byte, acmReg uint64) {
		measureOptions := []pcr.MeasureOption{
			pcr.SetFlow(pcr.FlowIntelCBnT0T),
			pcr.SetIBBHashDigest(tpm2.AlgSHA1),
			pcr.SetRegisters(registers.Registers{
				registers.ParseACMPolicyStatusRegister(acmReg),
			}),
		}
		measurements, _, debugInfo, err := pcr.GetMeasurements(firmware, 0, measureOptions...)
		require.NoError(t, err, fmt.Sprintf("debugInfo: '%v'", debugInfo))

		succeeded, _, acmPolicyStatus, err := ReproduceExpectedPCR0(
			logrusctx.NewContext(logger.LevelDebug),
			pcr0,
			pcr.FlowIntelCBnT0T,
			measurements,
			firmware.Buf(),
		)

		if bytes.Equal(pcr0, pcr0Invalid) {
			require.False(t, succeeded)
			require.Nil(t, acmPolicyStatus)
		} else {
			require.True(t, succeeded, "%v\n%v\n%v", err, measurements, debugInfo)
			require.Equal(t, uint64(correctACMRegValue), acmPolicyStatus.Raw())
		}
	}

	t.Run("test_uncorrupted", func(t *testing.T) { testACM(t, pcr0Correct, correctACMRegValue) })
	t.Run("test_corrupted_linear", func(t *testing.T) { testACM(t, pcr0Correct, correctACMRegValue+0x1c) })
	if enableCombinatorialStrategy {
		t.Run("test_corrupted_combinatorial", func(t *testing.T) { testACM(t, pcr0Correct, correctACMRegValue^0x10000000) })
	}
	t.Run("test_incompletePCR0_corruptedACM", func(t *testing.T) { testACM(t, pcr0Incomplete, correctACMRegValue+1) })
	t.Run("test_invalid_PCR0", func(t *testing.T) { testACM(t, pcr0Invalid, correctACMRegValue) })
}

func BenchmarkReproduceExpectedPCR0(b *testing.B) {
	firmware := getFirmware(b)

	const correctACMRegValue = 0x0000000200108681
	ctx := xcontext.Background()

	pcr0Correct := unhex(b, "F4D6D480F066F64A78598D82D1DEC77BBD53DEC1")
	pcr0Incomplete := unhex(b, "4CB03F39E94B0AB4AD99F9A54E3FD0DEFB0BB2D4")
	pcr0Invalid := unhex(b, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	var acmCorruptions []uint64
	if enableCombinatorialStrategy {
		acmCorruptions = append(acmCorruptions, []uint64{0x100000000, 0x100100000}...)
	}
	acmCorruptions = append(acmCorruptions, []uint64{0x1c, 0}...)

	for _, acmCorruption := range acmCorruptions {
		b.Run(fmt.Sprintf("acmCorruption_%X", acmCorruption), func(b *testing.B) {
			measureOptions := []pcr.MeasureOption{
				pcr.SetFlow(pcr.FlowIntelCBnT0T),
				pcr.SetIBBHashDigest(tpm2.AlgSHA1),
				pcr.SetRegisters(registers.Registers{
					registers.ParseACMPolicyStatusRegister(correctACMRegValue + acmCorruption),
				}),
			}
			measurements, _, _, err := pcr.GetMeasurements(firmware, 0, measureOptions...)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("correctPCR0", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _, _, _ = ReproduceExpectedPCR0(
						ctx,
						pcr0Correct,
						pcr.FlowIntelCBnT0T,
						measurements,
						firmware.Buf(),
					)
				}
			})

			b.Run("incompletePCR0", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _, _, _ = ReproduceExpectedPCR0(
						ctx,
						pcr0Incomplete,
						pcr.FlowIntelCBnT0T,
						measurements,
						firmware.Buf(),
					)
				}
			})

			b.Run("invalidPCR0", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _, _, _ = ReproduceExpectedPCR0(
						ctx,
						pcr0Invalid,
						pcr.FlowIntelCBnT0T,
						measurements,
						firmware.Buf(),
					)
				}
			})
		})
	}
}
