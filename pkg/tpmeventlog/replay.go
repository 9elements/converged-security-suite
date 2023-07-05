package tpmeventlog

import (
	"bytes"
	"fmt"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
)

// ParseLocality parses TPM locality from EV_NO_ACTION event corresponding
// to the TPM initialization.
func ParseLocality(eventData []byte) (uint8, error) {
	// There no known way to reliably detect the locality using the event log,
	// but here we will add working recipes for specific cases.

	// event.Data example: "StartupLocality\x00\x03"
	descrWords := bytes.SplitN(eventData, []byte{0}, 2)
	switch {
	case bytes.Equal(descrWords[0], []byte("StartupLocality")):
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

// Replay reproduces a PCR value given events, PCR index and hash algorithm.
func Replay(eventLog *TPMEventLog, pcrIndex pcr.ID, hashAlgo TPMAlgorithm, logOut io.Writer) ([]byte, error) {
	if logOut == nil {
		logOut = io.Discard
	}
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, ErrNotSupportedHashAlgo{TPMAlgo: hashAlgo}
	}
	hasher := hash.New()

	events, err := eventLog.FilterEvents(pcrIndex, hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("unable to filter events: %w", err)
	}

	// Set the initial value.
	//
	// Different PCR values has different rules how to set the initial value:
	// * PCR0 is initially filled with zeros, but with the last byte equals to TPM initialization locality.
	// * PCR1 is initially just filled with zeros.
	// * Some PCR values are initially filled with 0xFF-s.
	var result []byte
	switch pcrIndex {
	// We currently support only PCR0 and PCR1
	case 0:
		// The locality to be determined from EventLog, so do not initialize it, yet.
	case 1:
		// The initial value is always a bunch of zeros.
		result = make([]byte, hasher.Size())
		_, _ = fmt.Fprintf(logOut, "set(0x%X)\n", result)
	default:
		return nil, ErrNotSupportedIndex{Index: pcrIndex}
	}

	// Replay the log
	for _, event := range events {
		switch {
		case event.Type == EV_NO_ACTION:
			if len(result) != 0 {
				return nil, ErrUnexpectedEventType{Event: *event, Reason: "already initialized"}
			}
			switch pcrIndex {
			case 0:
				locality, err := ParseLocality(event.Data)
				if err != nil {
					return nil, fmt.Errorf("unable to parse locality: %w", err)
				}
				result = make([]byte, hasher.Size())
				result[len(result)-1] = locality
				_, _ = fmt.Fprintf(logOut, "set(0x%X)\n", result)
			default:
				return nil, ErrNotSupportedIndex{
					Index:       pcrIndex,
					Description: "measurement value init event is currently supported for PCR0 only",
				}
			}
		default:
			if len(result) == 0 {
				switch pcrIndex {
				case 0:
					// There was no event about PCR value initializing, therefore
					// assuming the zero value.
					result = make([]byte, hasher.Size())
					_, _ = fmt.Fprintf(logOut, "set(0x%X)\n", result)
				default:
					return nil, ErrNotSupportedIndex{Index: pcrIndex}
				}
			}

			_, _ = fmt.Fprintf(logOut, "%T(0x%X 0x%X)", hasher, result, event.Digest.Digest)
			if _, err := hasher.Write(result); err != nil {
				return nil, fmt.Errorf("unable to hash: %w", err)
			}
			if _, err := hasher.Write(event.Digest.Digest); err != nil {
				return nil, fmt.Errorf("unable to hash: %w", err)
			}
			result = hasher.Sum(nil)
			hasher.Reset()
			_, _ = fmt.Fprintf(logOut, " -> %X\n", result)
		}
	}

	return result, nil
}
