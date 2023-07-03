package datasources

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// Bytes is just a static set of bytes, which implements types.DataSource.
type Bytes types.RawBytes

var _ types.DataSource = (Bytes)(nil)

// Data implements DataSource.
func (d Bytes) Data(context.Context, *types.State) (*types.Data, error) {
	return types.NewData(types.RawBytes(d)), nil
}

// String implements fmt.Stringer.
func (d Bytes) String() string {
	return fmt.Sprintf("Bytes{%X}", []byte(d))
}
