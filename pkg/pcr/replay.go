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

	var result []byte
	for _, event := range events {
		measurementIDs := TPMEventTypeToMeasurementIDs(pcrIndex, event.Type)
		switch {
		case len(measurementIDs) == 0:
			return nil, ErrUnexpectedEventType{Event: *event, Reason: fmt.Sprintf("unknown event type: %v", event.Type)}
		case measurementIDs.Contains(MeasurementIDInit):
			if len(result) != 0 {
				return nil, ErrUnexpectedEventType{Event: *event, Reason: "already initialized"}
			}
			switch pcrIndex {
			case 0:
				locality, err := tpmeventlog.ParseLocality(event.Data)
				if err != nil {
					return nil, err
				}
				result = make([]byte, hasher.Size())
				result[len(result)-1] = locality
				fmt.Fprintf(logOut, "set(0x%X)\n", result)
			default:
				return nil, ErrNotSupportedIndex{Index: pcrIndex}
			}
		default:
			if len(result) == 0 {
				switch pcrIndex {
				case 0:
					// There was no event about PCR value initializing, therefore
					// assuming the zero value.
					result = make([]byte, hasher.Size())
					fmt.Fprintf(logOut, "set(0x%X)\n", result)
				default:
					return nil, ErrNotSupportedIndex{Index: pcrIndex}
				}
			}

			fmt.Fprintf(logOut, "%T(0x%X 0x%X)", hasher, result, event.Digest.Digest)
			hasher.Write(result)
			hasher.Write(event.Digest.Digest)
			result = hasher.Sum(nil)
			hasher.Reset()
			fmt.Fprintf(logOut, " -> %X\n", result)
		}
	}

	return result, nil
}
