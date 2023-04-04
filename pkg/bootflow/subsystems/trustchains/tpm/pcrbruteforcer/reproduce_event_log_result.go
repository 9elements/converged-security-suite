// This package needs deep redesigning: there are more and more ways to do
// brute-forcing, so these modules should be flattened out instead of going
// coupling every method among each other.

package pcrbruteforcer

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

func ptr[T any](in T) *T {
	return &in
}

type ReproduceEventLogEntry struct {
	Measurement       *types.MeasuredData
	Calculated        *tpm.EventLogEntry
	Expected          *tpmeventlog.Event
	ActionCoordinates *types.ActionCoordinates
	Status            ReproduceEventLogEntryStatus
}

type ReproduceEventLogEntryStatus int

const (
	ReproduceEventLogEntryStatusUndefined = ReproduceEventLogEntryStatus(iota)
	ReproduceEventLogEntryStatusMatch
	ReproduceEventLogEntryStatusMismatch
	ReproduceEventLogEntryStatusUnexpected
	ReproduceEventLogEntryStatusMissing
)

type ReproduceEventLogResult []ReproduceEventLogEntry

func (s ReproduceEventLogResult) CombineAsEventLog() tpm.EventLog {
	result := make(tpm.EventLog, 0, len(s))
	for _, e := range s {
		switch e.Status {
		case ReproduceEventLogEntryStatusMatch:
			result = append(result, *e.Calculated)
		case ReproduceEventLogEntryStatusMismatch:
			result = append(result, *e.Calculated, *convertTPMEventLogEntry(e.Expected))
		case ReproduceEventLogEntryStatusUnexpected:
			result = append(result, *convertTPMEventLogEntry(e.Expected))
		case ReproduceEventLogEntryStatusMissing:
			result = append(result, *e.Calculated)
		default:
			panic(fmt.Sprintf("supposed to be impossible: %v", e.Status))
		}
	}

	return result
}

func (s ReproduceEventLogResult) CombineAsCommandLog() tpm.CommandLog {
	extendOrInit := func(ev *tpm.EventLogEntry) tpm.Command {
		if ev.PCRIndex != 0 || ev.Type != tpmeventlog.EV_NO_ACTION {
			return &ev.CommandExtend
		}
		for _, b := range ev.Digest {
			if b != 0 {
				return &ev.CommandExtend
			}
		}

		locality, _ := tpmeventlog.ParseLocality(ev.Data)
		return tpm.NewCommandInit(locality)
	}

	result := make(tpm.CommandLog, 0, len(s))
	for _, e := range s {
		var (
			calculatedAction       types.Action
			calculatedActionCoords types.ActionCoordinates
		)
		if e.Measurement != nil {
			calculatedAction = e.Measurement.Action
			calculatedActionCoords = *e.ActionCoordinates
		}
		switch e.Status {
		case ReproduceEventLogEntryStatusMatch:
			result = append(result,
				tpm.CommandLogEntry{
					Command:          extendOrInit(e.Calculated),
					CauseCoordinates: calculatedActionCoords,
					CauseAction:      calculatedAction,
				},
				tpm.CommandLogEntry{
					Command: &tpm.CommandEventLogAdd{
						CommandExtend: e.Calculated.CommandExtend,
						Type:          e.Calculated.Type,
						Data:          e.Calculated.Data,
					},
					CauseCoordinates: calculatedActionCoords,
					CauseAction:      calculatedAction,
				},
			)
		case ReproduceEventLogEntryStatusMismatch:
			result = append(
				result,
				tpm.CommandLogEntry{
					Command:          extendOrInit(e.Calculated),
					CauseCoordinates: calculatedActionCoords,
					CauseAction:      calculatedAction,
				},
				tpm.CommandLogEntry{
					Command: &tpm.CommandEventLogAdd{
						CommandExtend: e.Calculated.CommandExtend,
						Type:          e.Calculated.Type,
						Data:          e.Calculated.Data,
					},
					CauseCoordinates: calculatedActionCoords,
					CauseAction:      calculatedAction,
				},
				tpm.CommandLogEntry{
					Command: extendOrInit(convertTPMEventLogEntry(e.Expected)),
				},
				tpm.CommandLogEntry{
					Command: &tpm.CommandEventLogAdd{
						CommandExtend: convertTPMEventLogEntry(e.Expected).CommandExtend,
						Type:          e.Expected.Type,
						Data:          e.Expected.Data,
					},
					CauseCoordinates: calculatedActionCoords,
					CauseAction:      calculatedAction,
				},
			)
		case ReproduceEventLogEntryStatusUnexpected:
			result = append(
				result,
				tpm.CommandLogEntry{
					Command: extendOrInit(convertTPMEventLogEntry(e.Expected)),
				},
				tpm.CommandLogEntry{
					Command: &tpm.CommandEventLogAdd{
						CommandExtend: convertTPMEventLogEntry(e.Expected).CommandExtend,
						Type:          e.Expected.Type,
						Data:          e.Expected.Data,
					},
					CauseCoordinates: calculatedActionCoords,
					CauseAction:      calculatedAction,
				},
			)
		case ReproduceEventLogEntryStatusMissing:
			result = append(
				result,
				tpm.CommandLogEntry{
					Command:          extendOrInit(e.Calculated),
					CauseCoordinates: calculatedActionCoords,
					CauseAction:      calculatedAction,
				},
				tpm.CommandLogEntry{
					Command: &tpm.CommandEventLogAdd{
						CommandExtend: e.Calculated.CommandExtend,
						Type:          e.Calculated.Type,
						Data:          e.Calculated.Data,
					},
					CauseCoordinates: calculatedActionCoords,
					CauseAction:      calculatedAction,
				},
			)
		default:
			panic(fmt.Sprintf("supposed to be impossible: %v", e.Status))
		}
	}

	return result
}

func convertTPMEventLogEntry(ev *tpmeventlog.Event) *tpm.EventLogEntry {
	if ev == nil {
		return nil
	}

	return &tpm.EventLogEntry{
		CommandExtend: tpm.CommandExtend{
			PCRIndex: ev.PCRIndex,
			HashAlgo: ev.Digest.HashAlgo,
			Digest:   ev.Digest.Digest,
		},
		Type: ev.Type,
		Data: ev.Data,
	}
}
