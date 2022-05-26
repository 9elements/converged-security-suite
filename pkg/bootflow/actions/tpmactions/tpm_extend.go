package tpmactions

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/trustchains"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/google/go-tpm/tpm2"
)

type TPMExtend struct {
	DataSource datasources.DataSource
	PCRIndex   pcrtypes.ID
	HashAlgo   tpm2.Algorithm
}

var _ types.Action = (*TPMExtend)(nil)

func NewTPMExtend(
	pcrIndex pcrtypes.ID,
	dataSource datasources.DataSource,
	hashAlgo tpm2.Algorithm,
) *TPMExtend {
	return &TPMExtend{
		DataSource: dataSource,
		PCRIndex:   pcrIndex,
		HashAlgo:   hashAlgo,
	}
}

func (ext *TPMExtend) Apply(state *types.State) error {
	data, err := ext.DataSource.Data(state)
	if err != nil {
		return fmt.Errorf("unable to extract the data: %w", err)
	}

	return trustchains.TPMFunc(state, func(tpm *trustchains.TPM) error {
		err := tpm.TPMExtend(ext.PCRIndex, ext.HashAlgo, data.Bytes())
		if err != nil {
			return fmt.Errorf("unable to extend: %w", err)
		}

		state.AddVerifiedData(tpm, *data)
		return nil
	})
}
