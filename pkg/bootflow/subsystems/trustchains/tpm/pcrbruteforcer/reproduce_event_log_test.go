package pcrbruteforcer

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors/intelactors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/intelsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
	"github.com/9elements/converged-security-suite/v2/testdata/firmware"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testFlow = types.Flow{
	commonsteps.SetActor(intelactors.PCH{}),
	commonsteps.SetActor(intelactors.ACM{}),
	tpmsteps.InitTPM(3, true),
	intelsteps.MeasurePCR0DATA{},
	commonsteps.SetActor(actors.PEI{}),
	tpmsteps.Measure(0, tpmeventlog.EV_S_CRTM_VERSION, datasources.Bytes(unhex(nil, "1EFB6B540C1D5540A4AD4EF4BF17B83A"))),
	tpmsteps.Measure(0, tpmeventlog.EV_EFI_PLATFORM_FIRMWARE_BLOB2, datasources.UEFIGUIDFirst([]guid.GUID{ffsConsts.GUIDDXEContainer, ffsConsts.GUIDDXE})),
	tpmsteps.Measure(0, tpmeventlog.EV_SEPARATOR, datasources.Bytes{0, 0, 0, 0}),
	commonsteps.SetActor(actors.DXE{}),
}

func unhex(fataler fataler, h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		if fataler == nil {
			panic(err)
		}
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
					Digest:   unhex(fataler, "C42FEDAD268200CB1D15F97841C344E79DAE3320"),
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

func dummyBoot() (*tpm.TPM, *bootengine.BootProcess) {
	tpmInstance := tpm.NewTPM()
	s := types.NewState()
	s.IncludeSubSystem(tpmInstance)
	s.IncludeSubSystem(intelpch.NewPCH())
	s.IncludeSystemArtifact(biosimage.New(firmware.FakeIntelFirmware))
	s.IncludeSystemArtifact(txtpublic.New(registers.Registers{
		registers.ParseACMPolicyStatusRegister(0x0000000200108681),
	}))
	s.SetFlow(testFlow)
	process := bootengine.NewBootProcess(s)
	return tpmInstance, process
}

func TestReproduceEventLog(t *testing.T) {
	ctx := logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logger.LevelTrace))

	t.Run("simple", func(t *testing.T) {
		eventLog := getTPMEventLog(t)

		_, process := dummyBoot()
		process.Finish(ctx)
		succeeded, acmPolicyStatus, issues, err := ReproduceEventLog(
			ctx,
			process,
			eventLog,
			tpmeventlog.TPMAlgorithmSHA1,
			DefaultSettingsReproduceEventLog(),
		)
		require.NoError(t, err)
		require.Len(t, issues, 0)
		require.True(t, succeeded)
		require.Nil(t, acmPolicyStatus)
	})

	t.Run("corrupted_ACM_POLICY_STATUS", func(t *testing.T) {
		tpmInstance, process := dummyBoot()
		regs, _ := txtpublic.Get(process.CurrentState)
		regs.Registers[0] = registers.ParseACMPolicyStatusRegister(0x0000000200108682)
		process.Finish(ctx)

		eventLog := getTPMEventLog(t)

		succeeded, acmPolicyStatus, issues, err := ReproduceEventLog(
			ctx,
			process,
			eventLog,
			tpmeventlog.TPMAlgorithmSHA1,
			DefaultSettingsReproduceEventLog(),
		)
		assert.NoError(t, err)
		assert.Len(t, issues, 1, fmt.Sprintf("%s\n%s\n%v", process, tpmInstance.EventLog, eventLog))
		assert.True(t, succeeded)
		require.NotNil(t, acmPolicyStatus)
		require.Equal(t, uint64(0x0000000200108681), acmPolicyStatus.Raw())

		// cleanup:
		regs.Registers[0] = registers.ParseACMPolicyStatusRegister(0x0000000200108681)
	})

	t.Run("extra_TPMEventLog_entries", func(t *testing.T) {
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

		_, process := dummyBoot()
		process.Finish(ctx)
		succeeded, acmPolicyStatus, issues, err := ReproduceEventLog(
			ctx,
			process,
			eventLog,
			tpmeventlog.TPMAlgorithmSHA1,
			DefaultSettingsReproduceEventLog(),
		)
		require.NoError(t, err)
		require.False(t, succeeded)
		require.Equal(t, []Issue{
			fmt.Errorf("unexpected entry in EventLog of type EV_EFI_VARIABLE_AUTHORITY (0x800000E0) and digest 0000000000000000000000000000000000000000 on evIdx==1; log entry analysis: <unable to get any info; event: {PCR:0, Type:EV_EFI_VARIABLE_AUTHORITY (0x800000E0), Digest:{Algo:SHA1, Digest:0x0000000000000000000000000000000000000000}, Data:0x696E6A6563746564}>"),
			fmt.Errorf("unexpected entry in EventLog of type EV_S_CRTM_CONTENTS (0x7) and digest 0000000000000000000000000000000000000000 on evIdx==2; log entry analysis: <unable to get any info; event: {PCR:0, Type:EV_S_CRTM_CONTENTS (0x7), Digest:{Algo:SHA1, Digest:0x0000000000000000000000000000000000000000}, Data:0x}>"),
		}, issues)
		require.Nil(t, acmPolicyStatus)
	})
}

func BenchmarkReproduceEventLog(b *testing.B) {
	ctx := context.Background()

	s := types.NewState()
	s.IncludeSubSystem(tpm.NewTPM())
	s.IncludeSubSystem(intelpch.NewPCH())
	s.IncludeSystemArtifact(biosimage.New(firmware.FakeIntelFirmware))
	s.SetFlow(testFlow)
	process := bootengine.NewBootProcess(s)
	process.Finish(ctx)

	eventLog := getTPMEventLog(b)

	for i := 0; i < b.N; i++ {
		_, _, _, err := ReproduceEventLog(
			ctx,
			process,
			eventLog,
			tpmeventlog.TPMAlgorithmSHA1,
			DefaultSettingsReproduceEventLog(),
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}
