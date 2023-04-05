package tpm

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// EventLog represents TPM Event Log.
type EventLog []EventLogEntry

func EventLogFromParsed(parsed *tpmeventlog.TPMEventLog) EventLog {
	result := make(EventLog, 0, len(parsed.Events))
	for _, ev := range parsed.Events {
		result = append(result, EventLogEntryFromParsed(ev))
	}
	return result
}

func EventLogEntryFromParsed(ev *tpmeventlog.Event) EventLogEntry {
	return EventLogEntry{
		CommandExtend: CommandExtend{
			PCRIndex: ev.PCRIndex,
			HashAlgo: ev.Digest.HashAlgo,
			Digest:   ev.Digest.Digest,
		},
		Type: ev.Type,
		Data: ev.Data,
	}
}

// EventLogEntry is a single entry of EventLog.
type EventLogEntry struct {
	CommandExtend
	Type tpmeventlog.EventType
	Data []byte
}

// Apply is just a placeholder which forbids to use this entry directly as a Command.
func (entry EventLogEntry) Apply() {}

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

// RestoreCommands returns a list of command logged by the EventLog.
func (log EventLog) RestoreCommands() []Command {
	result := make([]Command, 0, len(log)*2)

	for _, e := range log {
		if e.Type == tpmeventlog.EV_NO_ACTION {
			if e.PCRIndex == 0 {
				locality, err := tpmeventlog.ParseLocality(e.Data)
				if err == nil {
					result = append(result, &CommandInit{
						Locality: locality,
					})
				}
			}
			continue
		}

		cmd := &CommandExtend{
			PCRIndex: e.PCRIndex,
			HashAlgo: e.HashAlgo,
			Digest:   e.Digest,
		}
		result = append(
			result,
			cmd,
			&CommandEventLogAdd{
				CommandExtend: *cmd,
				Type:          e.Type,
				Data:          e.Data,
			},
		)
	}

	return result
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
