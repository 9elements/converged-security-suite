package datasources

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type StaticData types.Data

func (d *StaticData) Data(*types.State) (*types.Data, error) {
	return (*types.Data)(d), nil
}

func (d *StaticData) String() string {
	return fmt.Sprintf("StaticData{%#+v}", (*types.Data)(d))
}
