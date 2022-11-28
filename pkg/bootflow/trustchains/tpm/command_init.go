package tpm

import (
	"context"
	"fmt"
)

type CommandInit struct {
	Locality uint8
}

var _ Command = (*CommandInit)(nil)

func NewCommandInit(locality uint8) *CommandInit {
	return &CommandInit{
		Locality: locality,
	}
}

func (cmd *CommandInit) LogString() string {
	return fmt.Sprintf("TPMInit(%d)", cmd.Locality)
}

func (cmd *CommandInit) GoString() string {
	return cmd.LogString()
}

func (cmd *CommandInit) apply(_ context.Context, tpm *TPM) error {
	tpm.PCRValues = make(PCRValues, PCRRegistersAmount)

	supportedAlgos := SupportedHashAlgos()
	for _, hashAlgo := range supportedAlgos {
		h, err := hashAlgo.Hash()
		if err != nil {
			return fmt.Errorf("unable to initialize a hasher factory for hash algo %v", hashAlgo)
		}
		hasher := h.New()
		for pcrID := PCRID(0); pcrID < PCRRegistersAmount; pcrID++ {
			if tpm.PCRValues[pcrID] == nil {
				tpm.PCRValues[pcrID] = make([][]byte, tpmMaxHashAlgo+1)
			}
			tpm.PCRValues[pcrID][hashAlgo] = make([]byte, hasher.Size())
			pcrValue := tpm.PCRValues[pcrID][hashAlgo]
			switch pcrID {
			case 0:
				pcrValue[len(pcrValue)-1] = cmd.Locality
			case 1:
			default:
				return fmt.Errorf("unexpected PCR ID: %d", pcrID)
			}
		}
	}
	return nil
}
