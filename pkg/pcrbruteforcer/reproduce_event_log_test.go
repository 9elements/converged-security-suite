package pcrbruteforcer

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/9elements/converged-security-suite/v2/testdata/firmware"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

var ctx = logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logger.LevelTrace))

func unhex(fataler fataler, h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		fataler.Fatal(err)
	}
	return b
}

func getTPMEventLog(fataler fataler) *tpmeventlog.TPMEventLog {
	return &tpmeventlog.TPMEventLog{
		Events: []*tpmeventlog.Event{
			{
				PCRIndex: 0,
				Type:     tpmeventlog.EV_NO_ACTION,
				Data:     []byte("StartupLocality\000\003"),
				Digest: &tpmeventlog.Digest{
					HashAlgo: 4,
					Digest:   unhex(fataler, "0000000000000000000000000000000000000000"),
				},
			},
			{
				PCRIndex: 0,
				Type:     tpmeventlog.EV_S_CRTM_CONTENTS,
				Digest: &tpmeventlog.Digest{
					HashAlgo: 4,
					Digest:   unhex(fataler, "527C9A38B2F45FBF89C382547E0A0812722A47D3"),
				},
			},
			{
				PCRIndex: 0,
				Type:     tpmeventlog.EV_S_CRTM_VERSION,
				Digest: &tpmeventlog.Digest{
					HashAlgo: 4,
					Digest:   unhex(fataler, "C14F556E35C9BB45F189B03F383A6A3E31256681"),
				},
			},
			{
				PCRIndex: 0,
				Type:     tpmeventlog.EV_POST_CODE,
				Digest: &tpmeventlog.Digest{
					HashAlgo: 4,
					Digest:   unhex(fataler, "4C9836F73CC42ADBECE7D565B783E618B4A75C22"),
				},
			},
			{
				PCRIndex: 0,
				Type:     tpmeventlog.EV_SEPARATOR,
				Digest: &tpmeventlog.Digest{
					HashAlgo: 4,
					Digest:   unhex(fataler, "9069CA78E7450A285173431B3E52C5C25299E473"),
				},
			},
		},
	}
}

func TestReproduceEventLog(t *testing.T) {
	firmwareImage := firmware.FakeIntelFirmware

	firmware, err := uefi.ParseUEFIFirmwareBytes(firmwareImage)
	require.NoError(t, err)

	regs := registers.Registers{
		registers.ParseACMPolicyStatusRegister(0x0000000200108681),
	}

	measureOptions := []pcr.MeasureOption{
		pcr.SetFlow(pcr.FlowIntelCBnT0T),
		pcr.SetIBBHashDigest(tpm2.AlgSHA1),
		pcr.SetRegisters(regs),
	}

	t.Run("simple", func(t *testing.T) {
		measurements, _, debugInfo, err := pcr.GetMeasurements(ctx, firmware, 0, measureOptions...)
		require.NoError(t, err, fmt.Sprintf("debugInfo: '%v'", debugInfo))

		eventLog := getTPMEventLog(t)

		succeeded, acmPolicyStatus, issues, err := ReproduceEventLog(eventLog, tpmeventlog.TPMAlgorithmSHA1, measurements, firmwareImage, DefaultSettingsReproduceEventLog())
		require.NoError(t, err)
		require.Len(t, issues, 0)
		require.True(t, succeeded)
		require.Nil(t, acmPolicyStatus)
	})

	t.Run("corrupted_ACM_POLICY_STATUS", func(t *testing.T) {
		regs[0] = registers.ParseACMPolicyStatusRegister(0x0000000200108682)

		measurements, _, debugInfo, err := pcr.GetMeasurements(ctx, firmware, 0, measureOptions...)
		require.NoError(t, err, fmt.Sprintf("debugInfo: '%v'", debugInfo))

		eventLog := getTPMEventLog(t)

		succeeded, acmPolicyStatus, issues, err := ReproduceEventLog(eventLog, tpmeventlog.TPMAlgorithmSHA1, measurements, firmwareImage, DefaultSettingsReproduceEventLog())
		require.NoError(t, err)
		require.Len(t, issues, 1)
		require.True(t, succeeded)
		require.Equal(t, uint64(0x0000000200108681), acmPolicyStatus.Raw())

		// cleanup:
		regs[0] = registers.ParseACMPolicyStatusRegister(0x0000000200108681)
	})

	t.Run("extra_TPMEventLog_entries", func(t *testing.T) {
		measurements, _, debugInfo, err := pcr.GetMeasurements(ctx, firmware, 0, measureOptions...)
		require.NoError(t, err, fmt.Sprintf("debugInfo: '%v'", debugInfo))

		eventLog := getTPMEventLog(t)
		eventsOrig := eventLog.Events
		eventLog.Events = make([]*tpmeventlog.Event, len(eventsOrig)+2)
		eventLog.Events[0] = eventsOrig[0]
		eventLog.Events[1] = &tpmeventlog.Event{
			PCRIndex: 0,
			Type:     tpmeventlog.EV_EFI_VARIABLE_AUTHORITY, // a non-expected type at all
			Data:     []byte("injected"),
			Digest: &tpmeventlog.Digest{
				HashAlgo: 4,
				Digest:   make([]byte, sha1.Size),
			},
		}
		eventLog.Events[2] = &tpmeventlog.Event{
			PCRIndex: 0,
			Type:     tpmeventlog.EV_S_CRTM_CONTENTS, // same type as the next entry
			Digest: &tpmeventlog.Digest{
				HashAlgo: 4,
				Digest:   make([]byte, sha1.Size), // but different digest
			},
		}
		copy(eventLog.Events[3:], eventsOrig[1:])

		succeeded, acmPolicyStatus, issues, err := ReproduceEventLog(eventLog, tpmeventlog.TPMAlgorithmSHA1, measurements, firmwareImage, DefaultSettingsReproduceEventLog())
		require.NoError(t, err)
		require.False(t, succeeded)
		require.Equal(t, []Issue{
			fmt.Errorf("extra entry in EventLog of type 2147483872 (0x800000E0) on evIdx==1"),
			fmt.Errorf("extra entry in EventLog of type 7 (0x7) on evIdx==2"),
		}, issues)
		require.Nil(t, acmPolicyStatus)
	})
}

func BenchmarkReproduceEventLog(b *testing.B) {
	firmware := getFirmware(b)

	measureOptions := []pcr.MeasureOption{
		pcr.SetFlow(pcr.FlowIntelCBnT0T),
		pcr.SetIBBHashDigest(tpm2.AlgSHA1),
		pcr.SetRegisters(registers.Registers{
			registers.ParseACMPolicyStatusRegister(0x000000020010868A),
		}),
	}
	measurements, _, debugInfo, err := pcr.GetMeasurements(ctx, firmware, 0, measureOptions...)
	require.NoError(b, err, fmt.Sprintf("debugInfo: '%v'", debugInfo))

	eventLog := getTPMEventLog(b)

	for i := 0; i < b.N; i++ {
		_, _, _, err := ReproduceEventLog(eventLog, tpmeventlog.TPMAlgorithmSHA1, measurements, firmware.Buf(), DefaultSettingsReproduceEventLog())
		if err != nil {
			b.Fatal(err)
		}
	}
}
