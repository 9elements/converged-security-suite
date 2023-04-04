package tpm

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// EventLog represents TPM Event Log.
type EventLog []EventLogEntry

// EventLogEntry is a single entry of EventLog.
type EventLogEntry struct {
	CommandExtend
	Type tpmeventlog.EventType
	Data []byte
}

// String implements fmt.Stringer.
func (entry EventLogEntry) String() string {
	if len(entry.Data) == 0 {
		return fmt.Sprintf(
			"{PCR: %d, Alg: %s, Digest: %v, Type: %s}",
			entry.PCRIndex, entry.HashAlgo, entry.Digest, entry.Type,
		)
	}
	return fmt.Sprintf(
		"{PCR: %d, Alg: %s, Digest: %v, Type: %s, Data: 0x%X}",
		entry.PCRIndex, entry.HashAlgo, entry.Digest, entry.Type, entry.Data,
	)
}

func (log EventLog) Replay(pcrID PCRID, hashAlgo Algorithm, locality uint8) Digest {
	// TODO: consider removing the argument 'locality' (instead use Startup entry)

	h, err := hashAlgo.Hash()
	if err != nil {
		panic(fmt.Errorf("unable to initialize a hash function: %w", err))
	}
	hasher := h.New()

	if pcrID != 0 {
		// TODO: add code for initial values of other PCRs and delete this line:
		panic("currently only replay of PCR0 is supported")
	}

	result := make(Digest, h.Size())
	result[len(result)-1] = locality
	for _, ev := range log {
		if ev.PCRIndex != pcrID || ev.HashAlgo != hashAlgo {
			continue
		}
		hasher.Write(result)
		hasher.Write(ev.Digest)
		result = hasher.Sum(result[:0])
	}

	return result
}

// Add appends an entry to the EventLog.
func (log *EventLog) Add(extend CommandExtend, evType tpmeventlog.EventType, data []byte) {
	*log = append(*log, EventLogEntry{
		CommandExtend: extend,
		Type:          evType,
		Data:          data,
	})
}
