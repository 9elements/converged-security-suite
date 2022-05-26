package tpmactions

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/trustchains"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/google/go-tpm/tpm2"
)

type TPMEvent struct {
	DataSource datasources.DataSource
	PCRIndex   pcrtypes.ID
	EventData  []byte
}

var _ types.Action = (*TPMEvent)(nil)

func NewTPMEvent(
	pcrIndex pcrtypes.ID,
	dataSource datasources.DataSource,
	eventData []byte,
) *TPMEvent {
	return &TPMEvent{
		DataSource: dataSource,
		PCRIndex:   pcrIndex,
		EventData:  eventData,
	}
}

func (ev *TPMEvent) Apply(state *types.State) error {
	data, err := ev.DataSource.Data(state)
	if err != nil {
		return fmt.Errorf("unable to extract the data: %w", err)
	}

	return trustchains.TPMFunc(state, func(tpm *trustchains.TPM) error {
		for _, hashAlgo := range []tpm2.Algorithm{
			tpm2.AlgSHA1,
			tpm2.AlgSHA256,
		} {
			h, err := hashAlgo.Hash()
			if err != nil {
				return fmt.Errorf("unable to get hasher factory for algo %#v: %w", hashAlgo, err)
			}
			hasher := h.New()
			if _, err := hasher.Write(data.Bytes()); err != nil {
				return fmt.Errorf("unable to hash data with %T: %w", hasher, err)
			}
			digest := hasher.Sum(nil)

			if err := tpm.TPMExtend(ev.PCRIndex, hashAlgo, digest); err != nil {
				return fmt.Errorf("unable to extend: %w", err)
			}

			if err := tpm.TPMEventLogAdd(ev.PCRIndex, hashAlgo, digest, ev.EventData); err != nil {
				return fmt.Errorf("unable to add an entry to TPM EventLog: %w", err)
			}
		}

		state.AddVerifiedData(tpm, *data)
		return nil
	})
}
