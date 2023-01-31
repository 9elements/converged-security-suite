package tpmactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/google/go-tpm/tpm2"
)

// TPMEvent is a representation of `TPM2_PCR_Event`.
type TPMEventLogAdd struct {
	PCRIndex  pcrtypes.ID
	Algo      tpm2.Algorithm
	Digest    []byte
	EventData []byte
}

var _ types.Action = (*TPMEvent)(nil)

// NewTPMEvent returns a new instance of TPMEvent
func NewTPMEventLogAdd(
	pcrIndex pcrtypes.ID,
	algo tpm2.Algorithm,
	digest []byte,
	eventData []byte,
) *TPMEventLogAdd {
	return &TPMEventLogAdd{
		PCRIndex:  pcrIndex,
		Algo:      algo,
		Digest:    digest,
		EventData: eventData,
	}
}

// Apply implements types.Action.
func (ev *TPMEventLogAdd) Apply(ctx context.Context, state *types.State) error {

	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}

	if err := t.TPMEventLogAdd(ctx, ev.PCRIndex, ev.Algo, ev.Digest, ev.EventData, NewLogInfoProvider(state)); err != nil {
		return fmt.Errorf("unable to add an entry to TPM EventLog: %w", err)
	}

	return nil
}

// String implements fmt.Stringer.
func (ev TPMEventLogAdd) String() string {
	return fmt.Sprintf("TPMEventLogAdd(PCR: %d, Algo: %s, Digest: 0x%X, EventData: %X)", ev.PCRIndex, ev.Algo, ev.Digest, ev.EventData)
}
