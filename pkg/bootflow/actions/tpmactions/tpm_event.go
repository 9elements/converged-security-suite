package tpmactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
)

// TPMEvent is a representation of `TPM2_PCR_Event`.
type TPMEvent struct {
	DataSource types.DataSource
	PCRIndex   pcrtypes.ID
	EventData  []byte
}

var _ types.Action = (*TPMEvent)(nil)

// NewTPMEvent returns a new instance of TPMEvent
func NewTPMEvent(
	pcrIndex pcrtypes.ID,
	dataSource types.DataSource,
	eventData []byte,
) *TPMEvent {
	return &TPMEvent{
		DataSource: dataSource,
		PCRIndex:   pcrIndex,
		EventData:  eventData,
	}
}

// Apply implements types.Action.
func (ev *TPMEvent) Apply(ctx context.Context, state *types.State) error {
	data, err := ev.DataSource.Data(state)
	if err != nil {
		return fmt.Errorf("unable to extract the data: %w", err)
	}

	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}
	for _, hashAlgo := range tpm.SupportedHashAlgos() {
		h, err := hashAlgo.Hash()
		if err != nil {
			return fmt.Errorf("unable to get hasher factory for algo %v: %w", hashAlgo, err)
		}
		hasher := h.New()
		if _, err := hasher.Write(data.Bytes()); err != nil {
			return fmt.Errorf("unable to hash data with %T: %w", hasher, err)
		}
		digest := hasher.Sum(nil)

		if err := t.TPMExtend(ctx, ev.PCRIndex, hashAlgo, digest, NewLogInfoProvider(state)); err != nil {
			return fmt.Errorf("unable to extend: %w", err)
		}

		if err := t.TPMEventLogAdd(ctx, ev.PCRIndex, hashAlgo, digest, ev.EventData, NewLogInfoProvider(state)); err != nil {
			return fmt.Errorf("unable to add an entry to TPM EventLog: %w", err)
		}
	}

	state.AddMeasuredData(t, *data)
	return nil
}

func (ev TPMEvent) String() string {
	if len(ev.EventData) == 0 {
		return fmt.Sprintf("TPMEvent(PCR: %d, DataSource: %v)", ev.PCRIndex, ev.DataSource)
	}
	return fmt.Sprintf("TPMEvent(PCR: %d, DataSource: %v, EventData: %X)", ev.PCRIndex, ev.DataSource, ev.EventData)
}
