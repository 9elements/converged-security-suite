package tpmeventlog

import (
	"io"
	"io/ioutil"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"

	pcr "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
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

// Digest is the digest reported by an Event.
type Digest struct {
	HashAlgo TPMAlgorithm
	Digest   []byte
}

const (
	// TPMAlgorithmSHA1 is the identified of SHA1 algorithm.
	TPMAlgorithmSHA1 = tpm2.AlgSHA1

	// TPMAlgorithmSHA256 is the identified of SHA256 algorithm.
	TPMAlgorithmSHA256 = tpm2.AlgSHA256
)

// Parse parses a binary EventLog.
func Parse(input io.Reader) (*TPMEventLog, error) {
	b, err := ioutil.ReadAll(input)
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
