package datasources

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// StaticData is just a types.Data, which implements types.DataSource.
type StaticData types.Data

var _ types.DataSource = (*StaticData)(nil)

// Data implements types.DataSource.
func (d *StaticData) Data(*types.State) (*types.Data, error) {
	return (*types.Data)(d), nil
}

// String implements fmt.Stringer.
func (d *StaticData) String() string {
	return fmt.Sprintf("StaticData{%s}", format.NiceString((*types.Data)(d)))
}
