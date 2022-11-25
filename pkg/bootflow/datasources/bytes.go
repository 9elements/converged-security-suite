package datasources

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Bytes []byte

var _ types.DataSource = (Bytes)(nil)

func (d Bytes) Data(*types.State) (*types.Data, error) {
	return &types.Data{ForceBytes: d}, nil
}

func (d Bytes) GoString() string {
	return fmt.Sprintf("Bytes{%X}", []byte(d))
}
