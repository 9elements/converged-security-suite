package tpmactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/google/go-tpm/tpm2"
)

// TPMExtend is a representation of `TPM2_PCR_Extend`.
type TPMExtend struct {
	DataSource types.DataSource
	PCRIndex   pcrtypes.ID
	HashAlgo   tpm2.Algorithm
}

var _ types.Action = (*TPMExtend)(nil)

// NewTPMExtend returns a new instance of TPMEvent.
func NewTPMExtend(
	pcrIndex pcrtypes.ID,
	dataSource types.DataSource,
	hashAlgo tpm2.Algorithm,
) *TPMExtend {
	return &TPMExtend{
		DataSource: dataSource,
		PCRIndex:   pcrIndex,
		HashAlgo:   hashAlgo,
	}
}

// Apply implements types.Action.
func (ext *TPMExtend) Apply(ctx context.Context, state *types.State) error {
	data, err := ext.DataSource.Data(ctx, state)
	if err != nil {
		return fmt.Errorf("unable to extract the data: %w", err)
	}

	t, err := tpm.GetFrom(state)
	if err != nil {
		return err
	}
	err = t.TPMExtend(ctx, ext.PCRIndex, ext.HashAlgo, data.ConvertedBytes(), NewLogInfoProvider(state))
	if err != nil {
		return fmt.Errorf("unable to extend: %w", err)
	}

	state.AddMeasuredData(*data, t, ext.DataSource)
	return nil
}

func (ev TPMExtend) String() string {
	return fmt.Sprintf("TPMExtend(PCR: %d, DataSource: %v)", ev.PCRIndex, ev.DataSource)
}
