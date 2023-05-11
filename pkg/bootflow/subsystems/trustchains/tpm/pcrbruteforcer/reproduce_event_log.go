// This package needs deep redesigning: there are more and more ways to do
// brute-forcing, so these modules should be flattened out instead of going
// coupling every method among each other.

package pcrbruteforcer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"sync"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/dataconverters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/bruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/go-tpm/tpm2"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/xaionaro-go/unhash/pkg/unhash"
	"golang.org/x/exp/constraints"
)

// SettingsReproduceEventLog defines settings for internal bruteforce algorithms used in ReproduceEventLog
type SettingsReproduceEventLog struct {
	SettingsBruteforceACMPolicyStatus
	DisabledEventsMaxDistance uint64
	MaxDigestRangeGuesses     uint64
}

// DefaultSettingsReproduceEventLog returns recommended default PCR0 settings
func DefaultSettingsReproduceEventLog() SettingsReproduceEventLog {
	return SettingsReproduceEventLog{
		SettingsBruteforceACMPolicyStatus: DefaultSettingsBruteforceACMPolicyStatus(),
		DisabledEventsMaxDistance:         2, // arbitrary value based on previous experience, hoping to handle within a second; TODO: add benchmarks
		MaxDigestRangeGuesses:             100000000,
	}
}

func eventTypesString(types ...tpmeventlog.EventType) string {
	var result []string
	for _, t := range types {
		result = append(result, fmt.Sprintf("%d (0x%X)", uint32(t), uint32(t)))
	}
	return strings.Join(result, ", ")
}

// Issue is a non-critical problem
type Issue error

// ReproduceEventLog verifies measurements through TPM EventLog. If successful,
// the first returned variable is true; all mismatches are reported
// via `[]Issue`; and if ACM_POLICY_STATUS should be amended,
// then the updated value is returned as the second variable.
//
// Current algorithm already supports disabling measurements, may be in future
// we will return the rest amended measurements as well.
func ReproduceEventLog(
	ctx context.Context,
	calculated *bootengine.BootProcess,
	eventLogExpected *tpmeventlog.TPMEventLog,
	hashAlgo tpmeventlog.TPMAlgorithm,
	settings SettingsReproduceEventLog,
) (ReproduceEventLogResult, *registers.ACMPolicyStatus, []Issue, error) {
	var issues []Issue

	if eventLogExpected == nil {
		return nil, nil, issues, fmt.Errorf("TPM EventLog is not provided")
	}

	measurementsCalculated, eventsCalculated, eventsExpected, measurementDigests, coords, alignIssues, err := alignLogsAndMeasurements(
		ctx,
		calculated,
		&settings,
		eventLogExpected,
		hashAlgo,
	)
	logger.FromCtx(ctx).Tracef("measurementsCalculated == %v", measurementsCalculated)
	logger.FromCtx(ctx).Tracef("eventsCalculated == %v", eventsCalculated)
	logger.FromCtx(ctx).Tracef("eventsExpected == %v", eventsExpected)
	issues = append(issues, alignIssues...)
	if err != nil {
		return nil, nil, issues, err
	}

	txtPublicRegisters, _ := txtpublic.Get(calculated.CurrentState)

	var (
		updatedACMPolicyStatusValue *registers.ACMPolicyStatus
		logEntryExplainers          []*logEntryExplainer
	)

	result := make([]ReproduceEventLogEntry, 0, len(measurementsCalculated))
	for idx := 0; idx < len(measurementsCalculated); idx++ {
		m := measurementsCalculated[idx]
		mD := measurementDigests[idx]
		evC := eventsCalculated[idx]
		evE := eventsExpected[idx]
		coords := coords[idx]

		if evC == nil && evE != nil {
			logEntryExplainer := newLogEntryExplainer(ctx, calculated.CurrentState, m, evE)
			logEntryExplainers = append(logEntryExplainers, logEntryExplainer)
			issues = append(
				issues,
				IssueUnexpectedLogEntry{
					Index:             idx,
					Event:             evE,
					LogEntryExplainer: logEntryExplainer,
				},
			)
			result = append(result, ReproduceEventLogEntry{
				Expected: evE,
				Status:   ReproduceEventLogEntryStatusUnexpected,
			})
			continue
		}

		if evE == nil {
			if evC != nil {
				issues = append(issues, fmt.Errorf("missing entry (for measurement '%s') in EventLog (expected event types are: %s)", m, eventTypesString(evC.Type)))
				result = append(result, ReproduceEventLogEntry{
					Measurement:       m,
					Calculated:        evC,
					ActionCoordinates: coords,
					Status:            ReproduceEventLogEntryStatusMissing,
				})
				continue
			}
			return nil, nil, issues, fmt.Errorf("not supported: do not know how to handle the case when a measurement has no event log entry associated")
		}

		logger.FromCtx(ctx).Tracef("digest cmp: %X ? %s", evE.Digest.Digest, mD)
		if bytes.Equal(evE.Digest.Digest, mD) {
			result = append(result, ReproduceEventLogEntry{
				Measurement:       m,
				Calculated:        evC,
				Expected:          evE,
				ActionCoordinates: coords,
				Status:            ReproduceEventLogEntryStatusMatch,
			})
			// It matched, everything is OK, let's check next pair.
			continue
		}

		// It haven't matched, something is wrong...
		//
		// Let's try to remediate if we have an idea how to do that, or
		// just acknowledge a problem if we cannot remediate it.

		switch {
		case isPCRxDataMeasurement(m, txtPublicRegisters):
			// If this is the PCR0_DATA/PCR7_DATA measurement then it could be just
			// a corrupted ACM_POLICY_STATUS register value, let's try
			// to restore it.
			//
			correctedACMPolicyStatus, err := bruteForceACMPolicyStatus(m, txtPublicRegisters, evE.Digest.HashAlgo, evE.Digest.Digest, settings.SettingsBruteforceACMPolicyStatus)
			if err != nil {
				issues = append(issues, fmt.Errorf("PCR0_DATA measurement does not match the digest reported in EventLog and unable to brute force a possible bitflip: calculated:%s != given:0x%X", mD, evE.Digest.Digest))
				result = append(result, ReproduceEventLogEntry{
					Measurement:       m,
					Calculated:        evC,
					Expected:          evE,
					ActionCoordinates: coords,
					Status:            ReproduceEventLogEntryStatusMismatch,
				})
				continue
			}
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(correctedACMPolicyStatus))
			issues = append(issues, fmt.Errorf("changed ACM_POLICY_STATUS from %X to %X", m.References().BySystemArtifact(txtPublicRegisters).RawBytes(), buf))
			updatedACMPolicyStatusValue = &correctedACMPolicyStatus
			result = append(result, ReproduceEventLogEntry{
				Measurement:       m,
				Calculated:        evC,
				Expected:          evE,
				ActionCoordinates: coords,
				Status:            ReproduceEventLogEntryStatusMatch,
			})
		default:
			logEntryExplainer := newLogEntryExplainer(ctx, calculated.CurrentState, m, evE)
			logEntryExplainers = append(logEntryExplainers, logEntryExplainer)
			// I do not know how to remediate this problem.
			issues = append(
				issues,
				IssueLoggedDigestDoesNotMatch{
					Index:             idx,
					Measurement:       m,
					CalculatedDigest:  mD,
					Event:             evE,
					LogEntryExplainer: logEntryExplainer,
				},
			)

			result = append(result, ReproduceEventLogEntry{
				Measurement:       m,
				Calculated:        evC,
				Expected:          evE,
				ActionCoordinates: coords,
				Status:            ReproduceEventLogEntryStatusMismatch,
			})
		}
	}

	tryHardToExplainUnexpectedDigests(ctx, calculated, logEntryExplainers, settings)

	return result, updatedACMPolicyStatusValue, issues, nil
}

func tryHardToExplainUnexpectedDigests(
	ctx context.Context,
	calculated *bootengine.BootProcess,
	logEntryExplainers []*logEntryExplainer,
	settings SettingsReproduceEventLog,
) {
	fwImage, err := biosimage.Get(calculated.CurrentState)
	if err != nil {
		logger.FromCtx(ctx).Errorf("unable to get the BIOS image from the calculated state: %v", err)
		return
	}

	tpmInstance, err := tpm.GetFrom(calculated.CurrentState)
	if err != nil {
		logger.FromCtx(ctx).Errorf("unable to get the simulated TPM the calculated state: %v", err)
		return
	}

	digestsPerAlgo := map[tpm2.Algorithm][]unhash.Digest{}
	logEntryExplainersPerAlgo := map[tpm2.Algorithm][]*logEntryExplainer{}
	for _, logEntryExplainer := range logEntryExplainers {
		if logEntryExplainer.Measurement != nil {
			// already explained, no work to be done
			continue
		}
		hashAlgo := logEntryExplainer.Event.Digest.HashAlgo
		h, err := hashAlgo.Hash()
		if err != nil {
			logger.FromCtx(ctx).Warnf("unable to get hasher for algo %s", hashAlgo)
			continue
		}
		digest := logEntryExplainer.Event.Digest.Digest
		if len(digest) != h.Size() {
			logger.FromCtx(ctx).Warnf("digest size is invalid: actual:%d, expected:%d", len(digest), h.Size())
			continue
		}
		if isZeroSlice(digest) {
			continue
		}
		digestsPerAlgo[hashAlgo] = append(digestsPerAlgo[hashAlgo], digest)
		logEntryExplainersPerAlgo[hashAlgo] = append(logEntryExplainersPerAlgo[hashAlgo], logEntryExplainer)
	}

	for hashAlgo, digests := range digestsPerAlgo {
		h, err := hashAlgo.Hash()
		if err != nil {
			logger.FromCtx(ctx).Warnf("unable to get hasher for algo %s", hashAlgo)
			continue
		}
		unhashSettings := unhash.DefaultSearchInBinaryBlobSettings(fwImage.Content, h.New())
		unhashSettings.MaxGuesses = settings.MaxDigestRangeGuesses

		foundCh := make(chan unhash.FoundDigestSourceResult)
		go func() {
			_, _, err := unhash.FindPieceOfBinaryForDigest(
				ctx,
				unhash.FindDigestSourceAllDigests(ctx, foundCh, digests...),
				fwImage.Content,
				h.New,
				unhashSettings,
			)
			close(foundCh)
			errmon.ObserveErrorCtx(ctx, err)
		}()

		var (
			followupDigests            []unhash.Digest
			followupLogEntryExplainers []*logEntryExplainer
		)
		for found := range foundCh {
			ranges := pkgbytes.Ranges{{Offset: uint64(found.StartPos), Length: uint64(found.EndPos) - uint64(found.StartPos)}}

			logEntryExplainer := logEntryExplainersPerAlgo[hashAlgo][found.DigestIndex]
			logEntryExplainer.SetMeasurement(fwImage, tpmInstance, nil, nil, ranges)
			measuredBytes := fwImage.Content[found.StartPos:found.EndPos]
			if len(measuredBytes) != h.Size() {
				continue
			}

			if logEntryExplainer.EventDataParsed != nil {
				chunks := rangesToChunks(ctx, fwImage, logEntryExplainer.EventDataParsed.Ranges, nil)
				b := chunks.RawBytes()

				hasher := h.New()
				hasher.Write(b)
				dataHash := hasher.Sum(nil)
				if bytes.Equal(dataHash, measuredBytes) {
					logEntryExplainer.AddMeasurement(fwImage, digestAsTrustChain{}, dataconverters.NewHasher(h.New()), &biosimage.PhysMemMapper{}, logEntryExplainer.EventDataParsed.Ranges)
					continue
				}
			}

			// it looks like we measured a hash, let's investigate what this hash represents
			followupDigests = append(followupDigests, measuredBytes)
			followupLogEntryExplainers = append(followupLogEntryExplainers, logEntryExplainer)
		}

		if len(followupDigests) == 0 {
			continue
		}

		foundCh = make(chan unhash.FoundDigestSourceResult)
		go func() {
			_, _, err := unhash.FindPieceOfBinaryForDigest(
				ctx,
				unhash.FindDigestSourceAllDigests(ctx, foundCh, followupDigests...),
				fwImage.Content,
				h.New,
				unhashSettings,
			)
			close(foundCh)
			errmon.ObserveErrorCtx(ctx, err)
		}()

		for found := range foundCh {
			ranges := pkgbytes.Ranges{{Offset: uint64(found.StartPos), Length: uint64(found.EndPos) - uint64(found.StartPos)}}

			logEntryExplainer := followupLogEntryExplainers[found.DigestIndex]
			logEntryExplainer.AddMeasurement(fwImage, digestAsTrustChain{}, dataconverters.NewHasher(h.New()), nil, ranges)
		}
	}
}

type digestAsTrustChain struct{}

var _ types.TrustChain = digestAsTrustChain{}

func (digestAsTrustChain) IsInitialized() bool {
	return true
}

func (digestAsTrustChain) String() string {
	return "digest"
}

func isZeroSlice[E constraints.Ordered](s []E) bool {
	var zeroValue E
	for _, cmp := range s {
		if cmp != zeroValue {
			return false
		}
	}
	return true
}

func isPCRxDataMeasurement(
	m *types.MeasuredData,
	txtPublicRegisters *txtpublic.TXTPublic,
) bool {
	return getACMPolicyStatusRefFromMeasurement(m, txtPublicRegisters) != nil
}

func getACMPolicyStatusRefFromMeasurement(
	m *types.MeasuredData,
	txtPublicRegisters *txtpublic.TXTPublic,
) *types.Reference {
	if txtPublicRegisters == nil {
		return nil
	}

	// We assume this is a PCR0_DATA/PCR7_DATA measurement if it measures ACM_POLICY_STATUS registers
	// (and no other registers but ACM_POLICY_STATUS).

	refs := m.References().BySystemArtifact(txtPublicRegisters)
	if len(refs) != 1 {
		return nil
	}
	ref := refs[0]

	if len(ref.Ranges) != 1 {
		return nil
	}
	r := ref.Ranges[0]

	if r.Offset != registers.ACMPolicyStatusRegisterOffset || r.Length != 8 {
		return nil
	}

	return &ref
}

func bruteForceACMPolicyStatus(
	m *types.MeasuredData,
	txtPublicRegisters *txtpublic.TXTPublic,
	hashAlgo tpm2.Algorithm,
	expectedPCR0DATADigest tpm.Digest,
	settings SettingsBruteforceACMPolicyStatus,
) (registers.ACMPolicyStatus, error) {
	acmPolicyStatusRef := getACMPolicyStatusRefFromMeasurement(m, txtPublicRegisters)
	if acmPolicyStatusRef == nil {
		return 0, fmt.Errorf("excepted the find reference to the ACM_POLICY_STATUS register in the measurement, but haven't foundw")
	}

	pcr0Data := m.RawBytes()

	hashFactory, err := hashAlgo.Hash()
	if err != nil {
		return 0, fmt.Errorf("unable to initialize a hasher factory for algo %s: %w", hashAlgo, err)
	}

	type bruteForceACMPolicyStatusEventContext struct {
		Hasher hash.Hash
	}

	init := func() ([]byte, any, error) {
		buf := make([]byte, len(pcr0Data))
		copy(buf, pcr0Data)
		return buf, &bruteForceACMPolicyStatusEventContext{
			Hasher: hashFactory.New(),
		}, nil
	}

	check := func(_ctx any, pcr0Data []byte) (bool, error) {
		ctx := _ctx.(*bruteForceACMPolicyStatusEventContext)
		hasher := ctx.Hasher
		hasher.Reset()
		hasher.Write(pcr0Data)
		hashValue := hasher.Sum(nil)
		return bytes.Equal(hashValue, expectedPCR0DATADigest), nil
	}

	// try these in series because each completely fills the cpu
	strategies := []acmPolicyStatusBruteForceStrategy{
		newLinearSearch(settings.MaxACMPolicyLinearDistance, expectedPCR0DATADigest),
	}

	if settings.EnableACMPolicyCombinatorialStrategy {
		strategies = append(strategies, newCombinatorialSearch(settings.MaxACMPolicyCombinatorialDistance, expectedPCR0DATADigest))
	}

	for _, s := range strategies {
		reg, err := s.Process(init, check)
		if err != nil {
			return 0, fmt.Errorf("unable execute strategy %T: %w", s, err)
		}
		if reg != nil {
			return *reg, nil
		}
	}

	return 0, fmt.Errorf("unable to find the value")
}

func alignLogsAndMeasurements(
	ctx context.Context,
	calculated *bootengine.BootProcess,
	settings *SettingsReproduceEventLog,
	eventLogExpected *tpmeventlog.TPMEventLog,
	hashAlgo tpmeventlog.TPMAlgorithm,
) (
	measurementsCalculatedAligned []*types.MeasuredData,
	eventsCalculatedAligned []*tpm.EventLogEntry,
	eventsExpectedAligned []*tpmeventlog.Event,
	measurementDigestsAligned []tpm.Digest,
	coordsAligned []*types.ActionCoordinates,
	issues []Issue,
	err error,
) {
	fwImage, err := biosimage.Get(calculated.CurrentState)
	if err != nil {
		err = fmt.Errorf("BIOS image is not available: %w", err)
		return
	}

	measurementsCalculatedUnaligned, eventsCalculatedUnaligned, coordsUnaligned, err := alignLogAndMeasurements(
		ctx,
		calculated,
		0,
		hashAlgo,
	)
	if err != nil {
		err = fmt.Errorf("unable to align the calculated TPM measurements and the calculated TPM EventLog: %w", err)
		return
	}
	if len(measurementsCalculatedUnaligned) != len(eventsCalculatedUnaligned) {
		err = fmt.Errorf("internal error (should never happen): len(measurementsCalculatedUnaligned) != len(eventsCalculatedUnaligned): %d != %d", len(measurementsCalculatedUnaligned), len(eventsCalculatedUnaligned))
		return
	}
	logger.FromCtx(ctx).Tracef("measurementsCalculatedUnaligned == %v", measurementsCalculatedUnaligned)
	logger.FromCtx(ctx).Tracef("eventsCalculatedUnaligned == %v", eventsCalculatedUnaligned)

	eventsCalculatedAligned, eventsExpectedAligned, measurementDigestsAligned, issues, err = alignLogs(
		settings,
		eventsCalculatedUnaligned,
		eventLogExpected,
		fwImage,
		hashAlgo,
	)
	if err != nil {
		err = fmt.Errorf("unable to align the expected and calculated TPM EventLogs: %w", err)
		return
	}

	if len(eventsCalculatedAligned) != len(eventsExpectedAligned) || len(eventsCalculatedAligned) != len(measurementDigestsAligned) {
		err = fmt.Errorf("internal error (should never happen): len(eventsCalculatedAligned) != len(eventsExpectedAligned) || len(eventsCalculatedAligned) != len(measurementDigestsAligned): %d != %d || %d != %d", len(eventsCalculatedAligned), len(eventsExpectedAligned), len(eventsCalculatedAligned), len(measurementDigestsAligned))
		return
	}

	if len(measurementsCalculatedUnaligned) == len(eventsCalculatedAligned) {
		measurementsCalculatedAligned = measurementsCalculatedUnaligned
		coordsAligned = coordsUnaligned
		return
	}

	// If empty entries were injected into eventsCalculatedAligned to align with eventsExpectedAligned, then
	// we also need to add these empty entries to measurementsCalculatedAligned.

	measurementsCalculatedAligned = make([]*types.MeasuredData, len(eventsCalculatedAligned))
	coordsAligned = make([]*types.ActionCoordinates, len(eventsCalculatedAligned))
	for idxUnaligned, idxAligned := 0, 0; idxAligned < len(eventsCalculatedAligned); idxAligned++ {
		if idxUnaligned >= len(eventsCalculatedUnaligned) {
			break
		}
		evUnaligned := eventsCalculatedUnaligned[idxUnaligned]
		evAligned := eventsCalculatedAligned[idxAligned]
		if evAligned == evUnaligned {
			measurementsCalculatedAligned[idxAligned] = measurementsCalculatedUnaligned[idxUnaligned]
			coordsAligned[idxAligned] = coordsUnaligned[idxUnaligned]
			idxUnaligned++
			continue
		}
	}

	return
}

func alignLogAndMeasurements(
	ctx context.Context,
	calculated *bootengine.BootProcess,
	pcrID tpm.PCRID,
	hashAlgo tpm.Algorithm,
) (
	measurements []*types.MeasuredData,
	log []*tpm.EventLogEntry,
	coords []*types.ActionCoordinates,
	err error,
) {
	tpmInstance, err := tpm.GetFrom(calculated.CurrentState)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to get TPM: %w", err)
	}

	type stepResult struct {
		measurements []*types.MeasuredData
		eventLog     []*tpm.EventLogEntry
		coords       types.ActionCoordinates
	}

	measuredDataMap := map[types.Action]*types.MeasuredData{}
	for idx, m := range calculated.CurrentState.MeasuredData {
		if m.TrustChain != tpmInstance {
			continue
		}
		if m.Action == nil {
			return nil, nil, nil, fmt.Errorf("internal error: Action is nil at %v", m)
		}
		if _, ok := measuredDataMap[m.Action]; ok {
			return nil, nil, nil, fmt.Errorf("internal error: should never happen: measuredDataMap[%s] is already set", m.DataSource)
		}
		logger.FromCtx(ctx).Tracef("measuredDataMap[%v (%#+v)] = %v", m.Action, m.Action, calculated.CurrentState.MeasuredData[idx])
		measuredDataMap[m.Action] = &calculated.CurrentState.MeasuredData[idx]
	}

	tpmEventLog := tpmInstance.EventLog
	tpmEventLogIdx := 0
	stepIdx := -1
	var (
		prevCoords  types.ActionCoordinates
		stepResults []stepResult
	)
	for _, logEntry := range tpmInstance.CommandLog {
		coords := logEntry.CauseCoordinates
		if !coords.IsSameStep(prevCoords) {
			stepIdx++
			prevCoords = coords
		}
		if len(stepResults) <= stepIdx {
			stepResults = append(stepResults, stepResult{})
		}
		stepResult := &stepResults[stepIdx]
		switch cmd := logEntry.Command.(type) {
		case *tpm.CommandExtend:
			if cmd.PCRIndex != pcrID || cmd.HashAlgo != hashAlgo {
				continue
			}
			measurement := measuredDataMap[logEntry.CauseAction]
			logger.FromCtx(ctx).Tracef("tpm.CommandExtend: measuredDataMap[%v (%#v)]: %v", logEntry.CauseAction, logEntry.CauseAction, measurement)
			stepResult.measurements = append(stepResult.measurements, measurement)
		case *tpm.CommandEventLogAdd:
			logEntry := &tpmEventLog[tpmEventLogIdx]
			tpmEventLogIdx++
			if cmd.PCRIndex != pcrID || cmd.HashAlgo != hashAlgo {
				continue
			}
			stepResult.eventLog = append(stepResult.eventLog, logEntry)
		}
	}
	if tpmEventLogIdx != len(tpmEventLog) {
		return nil, nil, nil, fmt.Errorf("internal error: should never happen: %d != %d", tpmEventLogIdx, len(tpmEventLog))
	}

	for idx, stepResult := range stepResults {
		stepMeasurements := stepResult.measurements
		stepEvents := stepResult.eventLog

		// defensive code: just rechecking if magic above worked correctly.
		if len(stepMeasurements) > 0 && stepMeasurements[0] == nil {
			return nil, nil, nil, fmt.Errorf("internal error: stepMeasurements[0] == nil at idx:%d", idx)
		}

		logger.FromCtx(ctx).Tracef("stepResult[%d]: stepMeasurements == %v", idx, stepMeasurements)
		logger.FromCtx(ctx).Tracef("stepResult[%d]: stepEvents == %v", idx, stepEvents)
		if len(stepMeasurements) == 0 && len(stepEvents) == 0 {
			continue
		}
		switch {
		case len(stepMeasurements) == 0 && len(stepEvents) == 0:
			// NOOP
		case len(stepMeasurements) > 0 && len(stepEvents) > 0:
			if len(stepMeasurements) != len(stepEvents) {
				return nil, nil, nil, fmt.Errorf("do not know how to map measurements %s with log entries %s", stepMeasurements, stepEvents)
			}
			measurements = append(measurements, stepMeasurements...)
			log = append(log, stepEvents...)
			for range stepEvents {
				coords = append(coords, &stepResult.coords)
			}
		case len(stepMeasurements) > 0 && len(stepEvents) == 0:
			return nil, nil, nil, fmt.Errorf("not implemented, yet: measurements '%s' has no EventLog, this case is not supported, yet", stepMeasurements)
		case len(stepMeasurements) == 0 && len(stepEvents) > 0:
			measurements = append(measurements, make([]*types.MeasuredData, len(stepEvents))...)
			log = append(log, stepEvents...)
			for range stepEvents {
				coords = append(coords, &stepResult.coords)
			}
		default:
			panic("internal error: should be impossible, all the cases should be covered above in the code")
		}
		logger.FromCtx(ctx).Tracef("stepResult[%d]: measurements <- %v", idx, measurements)
		logger.FromCtx(ctx).Tracef("stepResult[%d]: eventLog <- %v", idx, log)
	}

	if len(measurements) != len(log) {
		return nil, nil, nil, fmt.Errorf("internal error: len(measurements) != len(log): %d != %d", len(measurements), len(log))
	}
	if len(measurements) != len(coords) {
		return nil, nil, nil, fmt.Errorf("internal error: len(measurements) != len(coords): %d != %d", len(measurements), len(coords))
	}
	return
}

func alignLogs(
	settings *SettingsReproduceEventLog,
	_eventsCalculated []*tpm.EventLogEntry,
	eventLogExpected *tpmeventlog.TPMEventLog,
	image *biosimage.BIOSImage,
	hashAlgo tpmeventlog.TPMAlgorithm,
) (
	eventsCalculated []*tpm.EventLogEntry,
	eventsExpected []*tpmeventlog.Event,
	digestsCalculated []tpm.Digest,
	issues []Issue,
	err error,
) {
	_eventsExpected, err := eventLogExpected.FilterEvents(0, hashAlgo)
	if err != nil {
		err = fmt.Errorf("unable to filter TPM EventLog events: %w", err)
		return
	}

	_digestsCalculated := make([]tpm.Digest, 0, len(_eventsCalculated))
	for _, evCalc := range _eventsCalculated {
		_digestsCalculated = append(_digestsCalculated, evCalc.Digest)
	}

	disabledExpectedEvents, disabledCalculatedEvents, distance, err := bruteForceAlignedEventLogs(
		settings,
		_eventsCalculated,
		_eventsExpected,
		_digestsCalculated,
	)
	if distance == 0 {
		eventsCalculated = _eventsCalculated
		eventsExpected = _eventsExpected
		digestsCalculated = _digestsCalculated
		if len(eventsExpected) != len(eventsCalculated) {
			err = fmt.Errorf("internal error (should not happen): %d != %d; distance miscalculation?", len(eventsExpected), len(eventsCalculated))
		}
		return
	}

	// a defensive check
	disabledExpectedEventsCount := 0
	for _, v := range disabledExpectedEvents {
		if v {
			disabledExpectedEventsCount++
		}
	}
	disabledCalculatedEventsCount := 0
	for _, v := range disabledCalculatedEvents {
		if v {
			disabledCalculatedEventsCount++
		}
	}
	if len(_eventsExpected)-disabledExpectedEventsCount != len(_eventsCalculated)-disabledCalculatedEventsCount {
		err = fmt.Errorf("internal error (should never happen): amounts of the aligned expected and calculated events are not equal: %d != %d", len(_eventsExpected)-disabledExpectedEventsCount, len(_eventsCalculated)-disabledCalculatedEventsCount)
		return
	}

	// constructing the aligned slices
	for idxE, idxC, outIdx := 0, 0, 0; idxE < len(_eventsExpected) || idxC < len(_eventsCalculated); outIdx++ {
		if idxE < len(_eventsExpected) && disabledExpectedEvents[idxE] {
			eventsCalculated = append(eventsCalculated, nil)
			eventsExpected = append(eventsExpected, _eventsExpected[idxE])
			digestsCalculated = append(digestsCalculated, nil)
			idxE++
			continue
		}
		if idxC < len(_eventsCalculated) && disabledCalculatedEvents[idxC] {
			eventsCalculated = append(eventsCalculated, _eventsCalculated[idxC])
			eventsExpected = append(eventsExpected, nil)
			digestsCalculated = append(digestsCalculated, _digestsCalculated[idxC])
			idxC++
			continue
		}
		eventsCalculated = append(eventsCalculated, _eventsCalculated[idxC])
		eventsExpected = append(eventsExpected, _eventsExpected[idxE])
		digestsCalculated = append(digestsCalculated, _digestsCalculated[idxC])
		idxE++
		idxC++
	}

	return
}

// bruteForceAlignedEventLogs finds an optimal solution to
// disable minimal subset of calculated and expected EventLog entries
// to get remaining events and measurements aligned.
//
// An optimal follows these rules:
// * We disable an event if it does not match by both: type and digest.
// * Prefer digest match over type match.
func bruteForceAlignedEventLogs(
	settings *SettingsReproduceEventLog,
	eventsCalculated []*tpm.EventLogEntry,
	eventsExpected []*tpmeventlog.Event,
	digestsCalculated []tpm.Digest,
) (disabledEvents []bool, disabledMeasurements []bool, curDistance uint64, err error) {
	curDistance = uint64(math.MaxUint64)
	if len(eventsCalculated) != len(digestsCalculated) {
		err = fmt.Errorf("internal error: len(eventLogCalculated) != len(digestsCalculated): %d != %d", len(eventsCalculated), len(digestsCalculated))
		return
	}

	disabledItemIdx := make([]bool, len(eventsExpected)+len(eventsCalculated))
	disabledEvents = disabledItemIdx[:len(eventsExpected)]
	disabledMeasurements = disabledItemIdx[len(eventsExpected):]

	if len(eventsExpected) == len(eventsCalculated) {
		curDistance = eventAndMeasurementsDistance(eventsExpected, disabledEvents, eventsCalculated, digestsCalculated, disabledMeasurements)
		if curDistance == 0 {
			return
		}
	}

	// Get prepared for bruteforcing.
	//
	// How to find the optimal solution?
	// We just calculate a distance metric and look for its minimum.
	// The distance metric is calculated in a way to satisfy the rules
	// listed in the description of "bruteForceAlignedEventsAndMeasurements" above.
	// See implementation of "eventAndMeasurementsDistance".

	var m sync.Mutex
	newDisabledMeasurements := make([]bool, len(disabledMeasurements))
	newDisabledEvents := make([]bool, len(disabledEvents))
	copy(newDisabledMeasurements, disabledMeasurements)
	copy(newDisabledEvents, disabledEvents)

	// First of all, align the amounts

	amountDiff := len(eventsExpected) - len(eventsCalculated)
	switch {
	case amountDiff == 0:
		// do nothing
	case amountDiff < 0:
		_, _ = bruteforcer.BruteForce(
			disabledMeasurements,
			1,
			uint64(-amountDiff),
			uint64(-amountDiff),
			nil,
			func(ctx any, data []bool) bool {
				distance := eventAndMeasurementsDistance(eventsExpected, disabledEvents, eventsCalculated, digestsCalculated, data)
				m.Lock()
				defer m.Unlock()
				if distance < curDistance {
					curDistance = distance
					copy(newDisabledMeasurements, data)
				}
				return distance == 0
			},
			bruteforcer.ApplyBitFlipsBools,
			0,
		)
		copy(disabledMeasurements, newDisabledMeasurements)
	case amountDiff > 0:
		_, _ = bruteforcer.BruteForce(
			disabledEvents,
			1,
			uint64(amountDiff),
			uint64(amountDiff),
			nil,
			func(ctx any, data []bool) bool {
				distance := eventAndMeasurementsDistance(eventsExpected, data, eventsCalculated, digestsCalculated, disabledMeasurements)
				m.Lock()
				defer m.Unlock()
				if distance < curDistance {
					curDistance = distance
					copy(newDisabledEvents, data)
				}
				return distance == 0
			},
			bruteforcer.ApplyBitFlipsBools,
			0,
		)
		copy(disabledEvents, newDisabledEvents)
	}

	// Now, align the content.

	type _context struct {
		locker                  sync.Mutex
		curDistance             uint64
		newDisabledMeasurements []bool
	}

	var disabledMeasurementsCount int
	for _, v := range disabledMeasurements {
		if v {
			disabledMeasurementsCount++
		}
	}
	_, _ = bruteforcer.BruteForce(
		disabledEvents,
		1,
		0,
		settings.DisabledEventsMaxDistance,
		func() (any, error) {
			_newDisabledMeasurements := make([]bool, len(disabledMeasurements))
			copy(_newDisabledMeasurements, disabledMeasurements)
			return &_context{
				curDistance:             math.MaxUint64,
				newDisabledMeasurements: _newDisabledMeasurements,
			}, nil
		},
		func(_ctx any, _disabledEvents []bool) bool {
			ctx := _ctx.(*_context)
			var disabledEventsCount int
			for _, v := range _disabledEvents {
				if v {
					disabledEventsCount++
				}
			}
			boolDistance := (disabledEventsCount - disabledMeasurementsCount) - (len(eventsExpected) - len(eventsCalculated))
			if boolDistance < 0 {
				return false
			}
			_, _ = bruteforcer.BruteForce(
				disabledMeasurements,
				1,
				uint64(boolDistance),
				uint64(boolDistance),
				nil,
				func(_ any, _disabledMeasurements []bool) bool {
					var newDisabledMeasurementsCount int
					for _, v := range _disabledMeasurements {
						if v {
							newDisabledMeasurementsCount++
						}
					}
					if disabledEventsCount-newDisabledMeasurementsCount != len(eventsExpected)-len(eventsCalculated) {
						// sometimes BruteForce will flip from true to false (not only from false to true),
						// we just skip these cases.
						return false
					}

					distance := eventAndMeasurementsDistance(eventsExpected, _disabledEvents, eventsCalculated, digestsCalculated, _disabledMeasurements)
					ctx.locker.Lock()
					defer ctx.locker.Unlock()
					if distance < ctx.curDistance {
						ctx.curDistance = distance
						copy(ctx.newDisabledMeasurements, _disabledMeasurements)
					}
					return distance == 0
				},
				bruteforcer.ApplyBitFlipsBools,
				0,
			)

			m.Lock()
			defer m.Unlock()
			if ctx.curDistance < curDistance {
				copy(newDisabledEvents, _disabledEvents)
				copy(newDisabledMeasurements, ctx.newDisabledMeasurements)
				curDistance = ctx.curDistance
			}
			return curDistance == 0
		},
		bruteforcer.ApplyBitFlipsBools,
		0,
	)
	copy(disabledEvents, newDisabledEvents)
	copy(disabledMeasurements, newDisabledMeasurements)

	return
}

func eventAndMeasurementsDistance(
	eventsExpected []*tpmeventlog.Event,
	evIsSkipped []bool,
	eventsCalculated []*tpm.EventLogEntry,
	digestsCalculated []tpm.Digest,
	mIsSkipped []bool,
) uint64 {
	distance := uint64(0)

	bigN := uint64(math.MaxUint32) // big enough to be always higher than amount of events and measurements

	for idxC, idxE := 0, 0; idxC < len(eventsCalculated) || idxE < len(eventsExpected); {
		if idxC < len(eventsCalculated) && mIsSkipped[idxC] {
			distance += bigN
			idxC++
			continue
		}
		if idxE < len(eventsExpected) && evIsSkipped[idxE] {
			distance += bigN
			idxE++
			continue
		}
		if idxC >= len(eventsCalculated) || idxE >= len(eventsExpected) {
			panic(fmt.Errorf("should never happen, because the resulting (after skipping) amount of events and measurements should be the same: %d >= %d || %d >= %d", idxC, len(eventsCalculated), idxE, len(eventsExpected)))
		}
		evC := eventsCalculated[idxC]
		digest := digestsCalculated[idxC]
		evE := eventsExpected[idxE]
		idxC++
		idxE++

		matchedType := evE.Type == evC.Type

		if len(evE.Digest.Digest) != len(digest) {
			panic(fmt.Errorf("should never happen, because the digest types guaranteed to be the same by the alignEventsAndMeasurementsByType implementation: len(ev.Digest.Digest) != len(mD): %d != %d", len(evE.Digest.Digest), len(digest)))
		}
		matchedDigest := bytes.Equal(evE.Digest.Digest, digest)

		if !matchedDigest {
			distance += 2*bigN - 1 // does not overweight a disabled event + disabled measurement
		}
		if !matchedType {
			distance += 2 // together with matchedDigest does overweight a disabled event + disabled measurement
		}
	}

	return distance
}
