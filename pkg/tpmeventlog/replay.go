package tpmeventlog

import (
	"bytes"

	pcr "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
)

// ParseLocality parses TPM locality from EV_NO_ACTION event corresponding
// to the TPM initialization.
func ParseLocality(eventData []byte) (uint8, error) {
	// There no known way to reliably detect the locality using the event log,
	// but here we will add working recipes for specific cases.

	// event.Data example: "StartupLocality\x00\x03"
	descrWords := bytes.Split(eventData, []byte{0})
	switch {
	case bytes.Compare(descrWords[0], []byte("StartupLocality")) == 0:
		if len(descrWords) > 0 && len(descrWords[1]) == 1 {
			return descrWords[1][0], nil
		}
	}
	return 0, ErrLocality{EventData: eventData}
}

// FilterEvents returns only the events which has a specified PCR index and
// a digest of a specified hash algorithm.
func (eventLog *TPMEventLog) FilterEvents(pcrIndex pcr.ID, hashAlgo TPMAlgorithm) ([]*Event, error) {
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, ErrNotSupportedHashAlgo{TPMAlgo: hashAlgo}
	}
	hasher := hash.HashFunc()

	var result []*Event
	for _, event := range eventLog.Events {
		if event.PCRIndex != pcrIndex {
			continue
		}
		if event.Digest == nil || event.Digest.HashAlgo != hashAlgo {
			continue
		}

		if len(event.Digest.Digest) != hasher.Size() {
			return nil, ErrInvalidDigestLength{Expected: hasher.Size(), Received: len(event.Digest.Digest)}
		}

		result = append(result, event)
	}

	return result, nil
}
