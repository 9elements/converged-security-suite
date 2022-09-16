package pcrbruteforcer

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// SettingsReproduceEventLog defines settings for internal bruteforce algorithms used in ReproduceEventLog
type SettingsReproduceEventLog struct {
	SettingsBruteforceACMPolicyStatus
}

// DefaultSettingsReproduceEventLog returns recommeneded default PCR0 settings
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
// the first returned variable is true; in any case all problems
// are reported through `error`; and if ACM_POLICY_STATUS should be amended,
// then the updated value is returned as the second variable.
//
// Current algorithm already supports disabling measurements, may be in future
// we will return the rest amended measurements as well.
//
// Currently we focus only on SHA1 measurements to simplify the code.
func ReproduceEventLog(
	eventLog *tpmeventlog.TPMEventLog,
	hashAlgo tpmeventlog.TPMAlgorithm,
	measurements pcr.Measurements,
	imageBytes []byte,
	settings SettingsReproduceEventLog,
) (bool, *registers.ACMPolicyStatus, []Issue, error) {
	var issues []Issue

	if eventLog == nil {
		return false, nil, nil, fmt.Errorf("TPM EventLog is not provided")
	}

	events, err := eventLog.FilterEvents(0, hashAlgo)
	if err != nil {
		return false, nil, nil, fmt.Errorf("unable to filter events: %w", err)
	}

	var filteredMeasurements pcr.Measurements
	for _, m := range measurements {
		if m.IsFake() && m.ID != pcr.MeasurementIDInit {
			continue
		}
		if len(m.EventLogEventTypes()) == 0 {
			issues = append(issues, fmt.Errorf("the flow requires a measurement, which is not expected to be logged into EventLog"))
			continue
		}
		filteredMeasurements = append(filteredMeasurements, m)
	}

	var updatedACMPolicyStatusValue *registers.ACMPolicyStatus
	evIdx, mIdx := 0, 0

	result := true
	for evIdx < len(events) && mIdx < len(filteredMeasurements) {
		m := filteredMeasurements[mIdx]
		mIdx++

		ev := eventLog.Events[evIdx]

		matched := false

		for _, eventType := range m.EventLogEventTypes() {
			if *eventType == ev.Type {
				matched = true
			}
		}

		if !matched {
			issues = append(issues, fmt.Errorf("missing measurement '%s' in EventLog (expected event types [%s], but received %d (0x%X) on evIdx==%d)", m.ID, eventTypesString(m.EventLogEventTypes()), ev.Type, ev.Type, evIdx))
			// We assume it happened because some measurements are missing
			// in the eventlog, therefore we skip the measurements hoping
			// that next measurement match with the EventLog entry.
			continue
		}
		evIdx++

		if m.ID == pcr.MeasurementIDInit {
			// Nothing to compare
			continue
		}

		hasherFactory, err := ev.Digest.HashAlgo.Hash()
		if err != nil {
			issues = append(issues, fmt.Errorf("invalid hash algo %d in measurement '%s' in EventLog (expected event types %v, but received %d on evIdx==%d)", ev.Digest.HashAlgo, m.ID, m.EventLogEventTypes(), ev.Type, evIdx))
			continue
		}
		hasher := hasherFactory.New()
		hasher.Write(m.CompileMeasurableData(imageBytes))
		mHash := hasher.Sum(nil)
		hasher.Reset()
		if bytes.Equal(mHash[:], ev.Digest.Digest) {
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
			correctedACMPolicyStatus, err := bruteForceACMPolicyStatus(*m, imageBytes, ev.Digest.Digest, settings.SettingsBruteforceACMPolicyStatus)
			if err != nil {
				issues = append(issues, fmt.Errorf("PCR0_DATA measurement does not match the digest reported in EventLog and unable to brute force a possible bitflip: %X != %X", mHash[:], ev.Digest.Digest))
				result = false
				continue
			}
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(correctedACMPolicyStatus))
			issues = append(issues, fmt.Errorf("changed ACM_POLICY_STATUS from %X to %X", m.Data[0].ForceData, buf))
			updatedACMPolicyStatusValue = &correctedACMPolicyStatus
		default:
			// I do not know how to remediate this problem.
			issues = append(issues, fmt.Errorf("measurement '%s' does not match the digest reported in EventLog: %X != %X", m.ID, mHash[:], ev.Digest.Digest))
			result = false
		}
	}
	if evIdx == 0 {
		// no-one EventLog entry matched, it could not be considered as "remediated"/"fixed".
		result = false
	}

	for ; mIdx < len(filteredMeasurements); mIdx++ {
		m := filteredMeasurements[mIdx]
		issues = append(issues, fmt.Errorf("missing measurement '%s' in EventLog", m.ID))
	}
	for ; evIdx < len(events); evIdx++ {
		ev := events[evIdx]
		issues = append(issues, fmt.Errorf("extra EventLog entry: evIdx == %d: type == %v", evIdx, ev.Type))
	}

	return result, updatedACMPolicyStatusValue, issues, nil
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
