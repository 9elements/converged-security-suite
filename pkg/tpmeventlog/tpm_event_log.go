package tpmeventlog

import (
	"fmt"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
)

// TPMEventLog is a parsed EventLog.
type TPMEventLog struct {
	Events []*Event
}

// TPMAlgorithm is an identified of a TPM-supported hash algorithm.
//
// See also: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf#page=42
type TPMAlgorithm = tpm2.Algorithm

// Event is a single entry of a parsed EventLog.
type Event struct {
	PCRIndex pcr.ID
	Type     EventType
	Data     []byte
	Digest   *Digest
}

// String implements fmt.Stringer
func (ev *Event) String() string {
	if ev == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{PCR:%d, Type:%s, Digest:%s, Data:0x%X}", ev.PCRIndex, ev.Type, ev.Digest, ev.Data)
}

// Digest is the digest reported by an Event.
type Digest struct {
	HashAlgo TPMAlgorithm
	Digest   []byte
}

// String implements fmt.Stringer
func (digest *Digest) String() string {
	if digest == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{Algo:%s, Digest:0x%X}", digest.HashAlgo, digest.Digest)
}

const (
	// TPMAlgorithmSHA1 is the identified of SHA1 algorithm.
	TPMAlgorithmSHA1 = tpm2.AlgSHA1

	// TPMAlgorithmSHA256 is the identified of SHA256 algorithm.
	TPMAlgorithmSHA256 = tpm2.AlgSHA256
)

// Parse parses a binary EventLog.
func Parse(input io.Reader) (*TPMEventLog, error) {
	b, err := io.ReadAll(input)
	if err != nil {
		return nil, ErrRead{Err: err}
	}
	eventLog, err := attest.ParseEventLog(b)
	if err != nil {
		return nil, ErrParse{Err: err}
	}

	result := &TPMEventLog{}
	for _, alg := range eventLog.Algs {
		for _, entry := range eventLog.Events(alg) {
			result.Events = append(result.Events, &Event{
				PCRIndex: pcr.ID(entry.Index),
				Type:     EventType(entry.Type),
				Data:     entry.Data,
				Digest: &Digest{
					HashAlgo: TPMAlgorithm(alg),
					Digest:   entry.Digest,
				},
			})
		}
	}

	return result, nil
}
