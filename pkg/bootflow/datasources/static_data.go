package datasources

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type StaticData struct {
	DataValue types.Data
}

func (d StaticData) Data(*types.State) (*types.Data, error) {
	return &d.DataValue, nil
}

func (d StaticData) GoString() string {
	return fmt.Sprintf("StaticData{%#+v}", d.DataValue)
}
