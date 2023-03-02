package amdactions

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/amdpsp"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type SetPSPVerifiedType struct {
	types.DataSource
}

var _ types.Action = (*SetPSPVerifiedType)(nil)

func SetPSPVerified(
	dataSource types.DataSource,
) *SetPSPVerifiedType {
	return &SetPSPVerifiedType{
		DataSource: dataSource,
	}
}

// Apply implements types.Action.
func (s *SetPSPVerifiedType) Apply(ctx context.Context, state *types.State) error {
	data, err := s.DataSource.Data(ctx, state)
	if err != nil {
		return fmt.Errorf("unable to extract the data: %w", err)
	}

	pch, err := amdpsp.GetFrom(state)
	if err != nil {
		return err
	}

	state.AddMeasuredData(*data, pch, s.DataSource)
	return nil
}

func (ev SetPSPVerifiedType) String() string {
	return fmt.Sprintf("SetPSPVerified(%v)", ev.DataSource)
}
