package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

type EventLog []EventLogEntry

type EventLogEntry struct {
	PCRIndex PCRID
	HashAlgo tpm2.Algorithm
	Digest   Digest
	Data     []byte
}

func (entry EventLogEntry) GoString() string {
	if len(entry.Data) == 0 {
		return fmt.Sprintf(
			"{PCR: %d, Alg: %s, Digest: %#v}",
			entry.PCRIndex, entry.HashAlgo, entry.Digest,
		)
	}
	return fmt.Sprintf(
		"{PCR: %d, Alg: %s, Digest: %#v, Data: 0x%X}",
		entry.PCRIndex, entry.HashAlgo, entry.Digest, entry.Data,
	)
}

func (log *EventLog) Add(pcrIndex PCRID, hashAlgo tpm2.Algorithm, digest, data []byte) {
	*log = append(*log, EventLogEntry{
		PCRIndex: pcrIndex,
		HashAlgo: hashAlgo,
		Digest:   digest,
		Data:     data,
	})
}
