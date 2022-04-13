package pcrbruteforcer

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/9elements/converged-security-suite/v2/pkg/bruteforcer"
	multierror "github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

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
	measurementsSHA1 pcr.Measurements,
	imageBytes []byte,
) (bool, *registers.ACMPolicyStatus, error) {
	if eventLog == nil {
		return false, nil, fmt.Errorf("TPM EventLog is not provided")
	}

	events, err := eventLog.FilterEvents(0, tpmeventlog.TPMAlgorithmSHA1)
	if err != nil {
		return false, nil, fmt.Errorf("unable to filter events: %w", err)
	}

	mErr := &multierror.MultiError{}

	var filteredMeasurements pcr.Measurements
	for _, m := range measurementsSHA1 {
		if m.IsFake() && m.ID != pcr.MeasurementIDInit {
			continue
		}
		if len(m.EventLogEventTypes()) == 0 {
			_ = mErr.Add(fmt.Errorf("the flow requires a measurement, which is not expected to be logged into EventLog"))
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
			_ = mErr.Add(fmt.Errorf("missing measurement '%s' in EventLog (expected event types %v, but received %d on evIdx==%d)", m.ID, m.EventLogEventTypes(), ev.Type, evIdx))
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

		mHash := sha1.Sum(m.CompileMeasurableData(imageBytes))
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
			correctedACMPolicyStatus, err := bruteForceACMPolicyStatus(*m, imageBytes, ev.Digest.Digest)
			if err != nil {
				_ = mErr.Add(fmt.Errorf("PCR0_DATA measurement does not match the digest reported in EventLog and unable to brute force a possible bitflip: %X != %X", mHash[:], ev.Digest.Digest))
				result = false
				continue
			}
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(correctedACMPolicyStatus))
			_ = mErr.Add(fmt.Errorf("changed ACM_POLICY_STATUS from %X to %X", m.Data[0].ForceData, buf))
			updatedACMPolicyStatusValue = &correctedACMPolicyStatus
		default:
			// I do not know how to remediate this problem.
			_ = mErr.Add(fmt.Errorf("measurement '%s' does not match the digest reported in EventLog: %X != %X", m.ID, mHash[:], ev.Digest.Digest))
			result = false
		}
	}
	if evIdx == 0 {
		// no-one EventLog entry matched, it could not be considered as "remediated"/"fixed".
		result = false
	}

	for ; mIdx < len(filteredMeasurements); mIdx++ {
		m := filteredMeasurements[mIdx]
		_ = mErr.Add(fmt.Errorf("missing measurement '%s' in EventLog", m.ID))
	}
	for ; evIdx < len(events); evIdx++ {
		ev := events[evIdx]
		_ = mErr.Add(fmt.Errorf("extra EventLog entry: evIdx == %d: type == %v", evIdx, ev.Type))
	}

	return result, updatedACMPolicyStatusValue, mErr.ReturnValue()
}

type bruteForceACMPolicyStatusEventContext struct {
	Hasher hash.Hash
	Buf    []byte
}

func bruteForceACMPolicyStatus(m pcr.Measurement, imageBytes []byte, expectedPCR0DATASHA1Digest []byte) (registers.ACMPolicyStatus, error) {
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

	// maxDistance is the maximal hamming distance to brute force to, it is
	// picked to 6, because it is maximal value for a reasonable brute-force
	// time (about 1 second).
	//
	// For benchmark details see also README.md of package `bruteforcer`.
	maxDistance := 6

	newContextFunc := func() (interface{}, error) {
		buf := make([]byte, len(pcr0Data))
		copy(buf, pcr0Data)
		return &bruteForceACMPolicyStatusEventContext{
			Hasher: sha1.New(),
			Buf:    buf,
		}, nil
	}

	verifyACMPolicyStatusFunc := func(_ctx interface{}, acmPolicyStatus []byte) bool {
		ctx := _ctx.(*bruteForceACMPolicyStatusEventContext)
		pcr0Data := ctx.Buf
		hasher := ctx.Hasher

		// overwriting the beginning of pcr0Data with new value of acmPolicyStatus.
		copy(pcr0Data, acmPolicyStatus)
		hasher.Write(pcr0Data)
		hashValue := hasher.Sum(nil)
		hasher.Reset()
		return bytes.Equal(hashValue, expectedPCR0DATASHA1Digest)
	}

	combination, err := bruteforcer.BruteForceBytes(acmPolicyStatus, uint64(maxDistance), newContextFunc, verifyACMPolicyStatusFunc, 0)
	if combination == nil {
		return 0, fmt.Errorf("unable to brute force: %w", err)
	}

	combination.ApplyBitFlips(acmPolicyStatus)
	return registers.ParseACMPolicyStatusRegister(binary.LittleEndian.Uint64(acmPolicyStatus)), nil
}
