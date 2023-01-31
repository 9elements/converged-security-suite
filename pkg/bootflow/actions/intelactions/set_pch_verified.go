package intelactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type SetPCHVerifiedT struct {
	types.DataSource
}

var _ types.Action = (*SetPCHVerifiedT)(nil)

func SetPCHVerified(
	dataSource types.DataSource,
) *SetPCHVerifiedT {
	return &SetPCHVerifiedT{
		DataSource: dataSource,
	}
}

// Apply implements types.Action.
func (s *SetPCHVerifiedT) Apply(ctx context.Context, state *types.State) error {
	data, err := s.DataSource.Data(state)
	if err != nil {
		return fmt.Errorf("unable to extract the data: %w", err)
	}

	pch, err := intelpch.GetFrom(state)
	if err != nil {
		return err
	}

	state.AddMeasuredData(*data, pch, s.DataSource)
	return nil
}

func (ev SetPCHVerifiedT) String() string {
	return fmt.Sprintf("SetPCHVerified(%v)", ev.DataSource)
}
