package datasources

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Concat []types.DataSource

var _ types.DataSource = (Concat)(nil)

func (c Concat) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	var result types.Data
	for idx, ds := range c {
		d, err := ds.Data(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("unable to get Data from DataSource#%d:%s: %w", idx, format.NiceString(ds), err)
		}

		if d.ForceBytes != nil {
			return nil, fmt.Errorf("data source Concat does not support ForceBytes")
		}
		if d.Converter != nil {
			return nil, fmt.Errorf("data source Concat does not support Converter")
		}
		if d.IsAlsoMeasurementOf != nil {
			return nil, fmt.Errorf("data source Concat does not support IsAlsoMeasurementOf")
		}

		result.References = append(result.References, d.References...)
	}
	return &result, nil
}
