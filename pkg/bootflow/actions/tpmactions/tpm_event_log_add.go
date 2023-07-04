package tpmactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// TPMEvent is a representation of `TPM2_PCR_Event`.
type TPMEventLogAdd struct {
	PCRIndex  pcr.ID
	Algo      tpm.Algorithm
	Digest    tpm.Digest
	Type      tpmeventlog.EventType
	EventData []byte
}

var _ types.Action = (*TPMEvent)(nil)

// NewTPMEvent returns a new instance of TPMEvent
func NewTPMEventLogAdd(
	pcrIndex pcr.ID,
	algo tpm.Algorithm,
	digest []byte,
	evType tpmeventlog.EventType,
	eventData []byte,
) *TPMEventLogAdd {
	return &TPMEventLogAdd{
		PCRIndex:  pcrIndex,
		Algo:      algo,
		Digest:    digest,
		Type:      evType,
		EventData: eventData,
	}
}

// Apply implements types.Action.
func (ev *TPMEventLogAdd) Apply(ctx context.Context, state *types.State) error {

	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}

	if err := t.TPMEventLogAdd(ctx, ev.PCRIndex, ev.Algo, ev.Digest, ev.Type, ev.EventData, NewLogInfoProvider(state)); err != nil {
		return fmt.Errorf("unable to add an entry to TPM EventLog: %w", err)
	}

	return nil
}

// String implements fmt.Stringer.
func (ev TPMEventLogAdd) String() string {
	if ev.EventData == nil {
		return fmt.Sprintf("TPMEventLogAdd(PCR: %d, Algo: %s, Digest: 0x%s)", ev.PCRIndex, ev.Algo, ev.Digest)
	}
	return fmt.Sprintf("TPMEventLogAdd(PCR: %d, Algo: %s, Digest: 0x%s, EventData: %X)", ev.PCRIndex, ev.Algo, ev.Digest, ev.EventData)
}
