package pcrbruteforcer

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"sync"

	"github.com/9elements/converged-security-suite/v2/pkg/bruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// SettingsReproduceEventLog defines settings for internal bruteforce algorithms used in ReproduceEventLog
type SettingsReproduceEventLog struct {
	SettingsBruteforceACMPolicyStatus
}

// DefaultSettingsReproduceEventLog returns recommended default PCR0 settings
func DefaultSettingsReproduceEventLog() SettingsReproduceEventLog {
	return SettingsReproduceEventLog{
		SettingsBruteforceACMPolicyStatus: DefaultSettingsBruteforceACMPolicyStatus(),
	}
}

func eventTypesString(types []*tpmeventlog.EventType) string {
	var result []string
	for _, t := range types {
		result = append(result, fmt.Sprintf("%d (0x%X)", uint32(*t), uint32(*t)))
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
//
// Currently we focus only on SHA1 measurements to simplify the code.
func ReproduceEventLog(
	eventLog *tpmeventlog.TPMEventLog,
	hashAlgo tpmeventlog.TPMAlgorithm,
	inMeasurements pcr.Measurements,
	imageBytes []byte,
	settings SettingsReproduceEventLog,
) (bool, *registers.ACMPolicyStatus, []Issue, error) {
	var issues []Issue

	if eventLog == nil {
		return false, nil, issues, fmt.Errorf("TPM EventLog is not provided")
	}

	events, measurements, measurementDigests, alignIssues, err := alignEventsAndMeasurements(eventLog, inMeasurements, imageBytes, hashAlgo)
	issues = append(issues, alignIssues...)
	if err != nil {
		return false, nil, issues, fmt.Errorf("unable to align Events and Measurements: %w", err)
	}

	if len(events) != len(measurements) || len(measurements) != len(measurementDigests) {
		return false, nil, issues, fmt.Errorf("internal error (should never happen): len(events) != len(measurements) || len(measurements) != len(measurementDigests): %d != %d || %d != %d", len(events), len(measurements), len(measurements), len(measurementDigests))
	}

	var updatedACMPolicyStatusValue *registers.ACMPolicyStatus

	isEventLogMatchesMeasurements := true
	for idx := 0; idx < len(measurements); idx++ {
		m := measurements[idx]
		mD := measurementDigests[idx]
		ev := events[idx]

		if m == nil {
			issues = append(issues, fmt.Errorf("unexpected entry in EventLog of type %d (0x%X) on evIdx==%d", ev.Type, ev.Type, idx))
			isEventLogMatchesMeasurements = false
			continue
		}

		if ev == nil {
			issues = append(issues, fmt.Errorf("missing entry (for measurement '%s') in EventLog (expected event types are: %s)", m.ID, eventTypesString(m.EventLogEventTypes())))
			isEventLogMatchesMeasurements = false
			continue
		}

		if m.ID == pcr.MeasurementIDInit {
			// Nothing to compare
			continue
		}

		if bytes.Equal(ev.Digest.Digest, mD) {
			// It matched, everything is OK, let's check next pair.
			continue
		}

		// It haven't matched, something is wrong...
		//
		// Let's try to remediate if we have an idea how to do that, or
		// just acknowledge a problem if we cannot remediate it.

		switch {
		case m.ID == pcr.MeasurementIDPCR0DATA:
			// If this is the PCR0_DATA measurement then it could be just
			// a corrupted ACM_POLICY_STATUS register value, let's try
			// to restore it.
			//
			correctedACMPolicyStatus, err := bruteForceACMPolicyStatus(*m, imageBytes, ev.Digest.Digest, settings.SettingsBruteforceACMPolicyStatus)
			if err != nil {
				issues = append(issues, fmt.Errorf("PCR0_DATA measurement does not match the digest reported in EventLog and unable to brute force a possible bitflip: %X != %X", mD, ev.Digest.Digest))
				isEventLogMatchesMeasurements = false
				continue
			}
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(correctedACMPolicyStatus))
			issues = append(issues, fmt.Errorf("changed ACM_POLICY_STATUS from %X to %X", m.Data[0].ForceData, buf))
			updatedACMPolicyStatusValue = &correctedACMPolicyStatus
		default:
			// I do not know how to remediate this problem.
			issues = append(issues, fmt.Errorf("measurement '%s' does not match the digest reported in EventLog: %X != %X", m.ID, mD, ev.Digest.Digest))
			isEventLogMatchesMeasurements = false
		}
	}

	return isEventLogMatchesMeasurements, updatedACMPolicyStatusValue, issues, nil
}

func bruteForceACMPolicyStatus(
	m pcr.Measurement,
	imageBytes []byte,
	expectedPCR0DATADigest []byte,
	settings SettingsBruteforceACMPolicyStatus,
) (registers.ACMPolicyStatus, error) {
	if len(m.Data) == 0 {
		return 0, fmt.Errorf("no data in the measurement")
	}
	if m.ID != pcr.MeasurementIDPCR0DATA {
		return 0, fmt.Errorf("PCR0_DATA excepted, but received %s", m.ID)
	}
	if len(m.Data) == 0 || m.Data[0].ID != pcr.DataChunkIDACMPolicyStatus {
		return 0, fmt.Errorf("excepted the first data chunk of PCR0_DATA be the ACM_POLICY_STATUS register")
	}

	m = *m.Copy()
	acmPolicyStatus := m.Data[0].ForceData
	if len(acmPolicyStatus) != 8 {
		return 0, fmt.Errorf("ACM POLICY STATUS register is expected to be 64bits, but it is %dbits", len(acmPolicyStatus)*8)
	}

	pcr0Data := m.CompileMeasurableData(imageBytes)

	var hashFuncFactory func() hash.Hash
	switch len(expectedPCR0DATADigest) {
	case sha1.Size:
		hashFuncFactory = sha1.New
	case sha256.Size:
		hashFuncFactory = sha256.New
	default:
		return 0, fmt.Errorf("invalid len of the expected PCR0_DATA digest: %d", len(expectedPCR0DATADigest))
	}

	type bruteForceACMPolicyStatusEventContext struct {
		Hasher hash.Hash
	}

	init := func() ([]byte, any, error) {
		buf := make([]byte, len(pcr0Data))
		copy(buf, pcr0Data)
		return buf, &bruteForceACMPolicyStatusEventContext{
			Hasher: hashFuncFactory(),
		}, nil
	}

	check := func(_ctx any, pcr0Data []byte) (bool, error) {
		ctx := _ctx.(*bruteForceACMPolicyStatusEventContext)
		hasher := ctx.Hasher
		hasher.Write(pcr0Data)
		hashValue := hasher.Sum(nil)
		hasher.Reset()
		return bytes.Equal(hashValue, expectedPCR0DATADigest), nil
	}

	// try these in series because each completely fills the cpu
	strategies := []acmPolicyStatusBruteForceStrategy{
		newLinearSearch(settings.MaxACMPolicyLinearDistance, imageBytes, expectedPCR0DATADigest),
	}

	if settings.EnableACMPolicyCombinatorialStrategy {
		strategies = append(strategies, newCombinatorialSearch(settings.MaxACMPolicyCombinatorialDistance, imageBytes, expectedPCR0DATADigest))
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

func alignEventsAndMeasurements(
	eventLog *tpmeventlog.TPMEventLog,
	inMeasurements pcr.Measurements,
	imageBytes []byte,
	hashAlgo tpmeventlog.TPMAlgorithm,
) (
	events []*tpmeventlog.Event,
	measurements pcr.Measurements,
	measurementDigests [][]byte,
	issues []Issue,
	err error,
) {
	inEvents, err := eventLog.FilterEvents(0, hashAlgo)
	if err != nil {
		err = fmt.Errorf("unable to filter TPM EventLog events: %w", err)
		return
	}

	var filteredMeasurements pcr.Measurements
	for _, m := range inMeasurements {
		if m.IsFake() && m.ID != pcr.MeasurementIDInit {
			continue
		}
		if len(m.EventLogEventTypes()) == 0 {
			issues = append(issues, fmt.Errorf("the flow requires a measurement, which is not expected to be logged into EventLog"))
			continue
		}
		filteredMeasurements = append(filteredMeasurements, m)
	}
	inMeasurements = filteredMeasurements

	hasherFactory, err := hashAlgo.Hash()
	if err != nil {
		err = fmt.Errorf("unable to initialize a hash function for algorithm %#v", hashAlgo)
		return
	}

	inMeasurementDigests := make([][]byte, 0, len(inMeasurements))
	for _, m := range inMeasurements {
		var hash []byte
		hash, err = m.Calculate(imageBytes, hasherFactory.New())
		if err != nil {
			err = fmt.Errorf("unable to cache measurement %#+v: %w", *m, err)
			return
		}
		inMeasurementDigests = append(inMeasurementDigests, hash)
	}

	disabledEvents, disabledMeasurements, distance, err := bruteForceAlignedEventsAndMeasurements(inEvents, inMeasurements, inMeasurementDigests)
	if distance == 0 {
		measurements = inMeasurements
		measurementDigests = inMeasurementDigests
		events = inEvents
		if len(measurements) != len(events) {
			err = fmt.Errorf("internal error (should not happen): %d != %d; distance miscalculation?", len(measurements), len(events))
		}
		return
	}

	// a defensive check
	disabledEventsCount := 0
	for _, v := range disabledEvents {
		if v {
			disabledEventsCount++
		}
	}
	disabledMeasurementsCount := 0
	for _, v := range disabledMeasurements {
		if v {
			disabledMeasurementsCount++
		}
	}
	if len(inEvents)-disabledEventsCount != len(inMeasurements)-disabledMeasurementsCount {
		err = fmt.Errorf("internal error (should never happen): amounts of aligned events and measurements are not equal: %d != %d", len(inEvents)-disabledEventsCount, len(inMeasurements)-disabledMeasurementsCount)
		return
	}

	// constructing the aligned slices
	for evIdx, mIdx, outIdx := 0, 0, 0; evIdx < len(inEvents) || mIdx < len(inMeasurements); outIdx++ {
		if evIdx < len(inEvents) && disabledEvents[evIdx] {
			events = append(events, inEvents[evIdx])
			measurementDigests = append(measurementDigests, nil)
			measurements = append(measurements, nil)
			evIdx++
			continue
		}
		if mIdx < len(inMeasurements) && disabledMeasurements[mIdx] {
			events = append(events, nil)
			measurementDigests = append(measurementDigests, inMeasurementDigests[mIdx])
			measurements = append(measurements, inMeasurements[mIdx])
			mIdx++
			continue
		}
		events = append(events, inEvents[evIdx])
		measurementDigests = append(measurementDigests, inMeasurementDigests[mIdx])
		measurements = append(measurements, inMeasurements[mIdx])
		evIdx++
		mIdx++
	}

	return
}

// bruteForceAlignedEventsAndMeasurements finds an optimal solution of
// disabled events and measurements to get remaining events and measurements
// aligned.
//
// An optimal follows these rules:
// * We disable an event or a measurement only if it does not match by both: type and digest.
// * Prefer digest match over type match.
func bruteForceAlignedEventsAndMeasurements(
	events []*tpmeventlog.Event,
	measurements pcr.Measurements,
	measurementDigests [][]byte,
) (disabledEvents []bool, disabledMeasurements []bool, curDistance uint64, err error) {
	curDistance = uint64(math.MaxUint64)
	if len(measurements) != len(measurementDigests) {
		err = fmt.Errorf("internal error: len(measurements) != len(measurementDigests): %d != %d", len(measurements), len(measurementDigests))
		return
	}

	disabledItemIdx := make([]bool, len(events)+len(measurements))
	disabledEvents = disabledItemIdx[:len(events)]
	disabledMeasurements = disabledItemIdx[len(events):]

	if len(events) == len(measurements) {
		curDistance = eventAndMeasurementsDistance(events, disabledEvents, measurements, measurementDigests, disabledMeasurements)
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

	amountDiff := len(events) - len(measurements)
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
				distance := eventAndMeasurementsDistance(events, disabledEvents, measurements, measurementDigests, data)
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
				distance := eventAndMeasurementsDistance(events, data, measurements, measurementDigests, disabledMeasurements)
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
		5, // arbitrary value based on previous experience, hoping to handle within a second; TODO: add benchmarks
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
			boolDistance := (disabledEventsCount - disabledMeasurementsCount) - (len(events) - len(measurements))
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
					if newDisabledMeasurementsCount != disabledEventsCount+boolDistance {
						// sometimes BruteForce will flip from true to false (not only from false to true),
						// we just skip these cases.
						return false
					}

					distance := eventAndMeasurementsDistance(events, _disabledEvents, measurements, measurementDigests, _disabledMeasurements)
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
	events []*tpmeventlog.Event,
	evIsSkipped []bool,
	measurements pcr.Measurements,
	measurementDigests [][]byte,
	mIsSkipped []bool,
) uint64 {
	distance := uint64(0)

	bigN := uint64(math.MaxUint32) // big enough to be always higher than amount of events and measurements

	for mIdx, evIdx := 0, 0; mIdx < len(measurements) || evIdx < len(events); {
		if mIdx < len(measurements) && mIsSkipped[mIdx] {
			distance += bigN
			mIdx++
			continue
		}
		if evIdx < len(events) && evIsSkipped[evIdx] {
			distance += bigN
			evIdx++
			continue
		}
		if mIdx >= len(measurements) || evIdx >= len(events) {
			panic(fmt.Errorf("should never happen, because the resulting (after skipping) amount of events and measurements should be the same: %d >= %d || %d >= %d", mIdx, len(measurements), evIdx, len(events)))
		}
		m := measurements[mIdx]
		mD := measurementDigests[mIdx]
		ev := events[evIdx]
		mIdx++
		evIdx++

		matchedType := false
		for _, eventType := range m.EventLogEventTypes() {
			if *eventType == ev.Type {
				matchedType = true
			}
		}

		if !m.IsFake() && len(ev.Digest.Digest) != len(mD) {
			panic(fmt.Errorf("should never happen, because the digest types guaranteed to be the same by the alignEventsAndMeasurementsByType implementation: len(ev.Digest.Digest) != len(mD): %d != %d", len(ev.Digest.Digest), len(mD)))
		}
		matchedDigest := bytes.Equal(ev.Digest.Digest, mD)

		if !matchedDigest {
			distance += 2*bigN - 1 // does not overweight a disabled event + disabled measurement
		}
		if !matchedType {
			distance += 2 // together with matchedDigest does overweight a disabled event + disabled measurement
		}
	}

	return distance
}
