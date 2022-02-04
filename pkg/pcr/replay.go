package pcr

import (
	"fmt"
	"io"
	"io/ioutil"

	pcr "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// Replay reproduces a PCR value given events, PCR index and hash algorithm.
func Replay(eventLog *tpmeventlog.TPMEventLog, pcrIndex pcr.ID, hashAlgo tpmeventlog.TPMAlgorithm, logOut io.Writer) ([]byte, error) {
	if logOut == nil {
		logOut = ioutil.Discard
	}
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, tpmeventlog.ErrNotSupportedHashAlgo{TPMAlgo: hashAlgo}
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
		measurementIDs := TPMEventTypeToMeasurementIDs(pcrIndex, event.Type)
		switch {
		case len(measurementIDs) == 0 && len(result) == 0:
			// The PCR value is not initialized, and we cannot determine which event log entry contains
			// the information to initialize it.
			return nil, ErrUnexpectedEventType{Event: *event, Reason: fmt.Sprintf("unknown event type: %v", event.Type)}
		case measurementIDs.Contains(MeasurementIDInit):
			if len(result) != 0 {
				return nil, ErrUnexpectedEventType{Event: *event, Reason: "already initialized"}
			}
			switch pcrIndex {
			case 0:
				locality, err := tpmeventlog.ParseLocality(event.Data)
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
