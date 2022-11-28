package datasources

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// Bytes is just a static set of bytes, which implements types.DataSource.
type Bytes []byte

var _ types.DataSource = (Bytes)(nil)

// Data implements DataSource.
func (d Bytes) Data(*types.State) (*types.Data, error) {
	return &types.Data{ForceBytes: d}, nil
}

// String implements fmt.Stringer.
func (d Bytes) String() string {
	return fmt.Sprintf("Bytes{%X}", []byte(d))
}
