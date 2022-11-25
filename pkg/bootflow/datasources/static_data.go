package datasources

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type StaticData []byte

func (d StaticData) Data(*types.State) (*types.Data, error) {
	return &types.Data{ForceBytes: d}, nil
}

func (d StaticData) GoString() string {
	return fmt.Sprintf("StaticData{%X}", []byte(d))
}