package tpm

import (
	"fmt"
)

// EventLog represents TPM Event Log.
type EventLog []EventLogEntry

// EventLogEntry is a single entry of EventLog.
type EventLogEntry struct {
	CommandExtend
	Data []byte
}

// String implements fmt.Stringer.
func (entry EventLogEntry) String() string {
	if len(entry.Data) == 0 {
		return fmt.Sprintf(
			"{PCR: %d, Alg: %s, Digest: %v}",
			entry.PCRIndex, entry.HashAlgo, entry.Digest,
		)
	}
	return fmt.Sprintf(
		"{PCR: %d, Alg: %s, Digest: %v, Data: 0x%X}",
		entry.PCRIndex, entry.HashAlgo, entry.Digest, entry.Data,
	)
}

// Add appends an entry to the EventLog.
func (log *EventLog) Add(extend CommandExtend, data []byte) {
	*log = append(*log, EventLogEntry{
		CommandExtend: extend,
		Data:          data,
	})
}
