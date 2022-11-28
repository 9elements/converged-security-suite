package tpm

import (
	"fmt"
)

type EventLog []EventLogEntry

type EventLogEntry struct {
	CommandExtend
	Data []byte
}

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

func (log *EventLog) Add(extend CommandExtend, data []byte) {
	*log = append(*log, EventLogEntry{
		CommandExtend: extend,
		Data:          data,
	})
}
