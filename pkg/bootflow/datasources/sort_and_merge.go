package datasources

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type SortAndMergeType struct {
	types.DataSource
}

func SortAndMerge(ds types.DataSource) SortAndMergeType {
	return SortAndMergeType{
		DataSource: ds,
	}
}

var _ types.DataSource = (*SortAndMergeType)(nil)

func (m SortAndMergeType) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	d, err := m.DataSource.Data(ctx, s)
	if err != nil {
		return nil, err
	}

	if d.ForcedBytes() != nil {
		return nil, fmt.Errorf("data source SortAndMerge does not support ForcedBytes")
	}
	if d.Converter != nil {
		return nil, fmt.Errorf("data source SortAndMerge does not support Converter")
	}

	refs := d.References()
	refs.SortAndMerge()
	return types.NewReferencesData(refs), nil
}
