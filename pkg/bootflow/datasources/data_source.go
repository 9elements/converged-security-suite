package datasources

import "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"

type DataSource interface {
	Data(*types.State) (*types.Data, error)
}
