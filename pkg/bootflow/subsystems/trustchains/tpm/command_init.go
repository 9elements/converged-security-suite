package tpm

import (
	"context"
	"fmt"
)

// CommandInit represents _TPM_init + TPM2_Startup(CLEAR).
type CommandInit struct {
	Locality uint8
}

var _ Command = (*CommandInit)(nil)

// NewCommandInit returns a new instance of CommandInit.
func NewCommandInit(locality uint8) *CommandInit {
	return &CommandInit{
		Locality: locality,
	}
}

// LogString implements Command.
func (cmd *CommandInit) LogString() string {
	return fmt.Sprintf("TPMInit(%d)", cmd.Locality)
}

// String implements fmt.Stringer.
func (cmd *CommandInit) String() string {
	return cmd.LogString()
}

// apply implements Command.
func (cmd *CommandInit) Apply(_ context.Context, tpm *TPM) error {
	if tpm.IsInitialized() {
		return fmt.Errorf("TPM is already initialized")
	}

	if cap(tpm.PCRValues) >= PCRRegistersAmount {
		tpm.PCRValues = tpm.PCRValues[:PCRRegistersAmount]
	} else {
		tpm.PCRValues = make(PCRValues, PCRRegistersAmount)
	}

	supportedAlgos := SupportedHashAlgos()
	for _, hashAlgo := range supportedAlgos {
		h, err := hashAlgo.Hash()
		if err != nil {
			return fmt.Errorf("unable to initialize a hasher factory for hash algo %v", hashAlgo)
		}
		hasher := h.New()
		for pcrID := PCRID(0); pcrID < PCRRegistersAmount; pcrID++ {
			banksPerPCR := tpmMaxHashAlgo + 1
			if cap(tpm.PCRValues[pcrID]) >= int(banksPerPCR) {
				tpm.PCRValues[pcrID] = tpm.PCRValues[pcrID][:banksPerPCR]
			} else {
				tpm.PCRValues[pcrID] = make([]Digest, tpmMaxHashAlgo+1)
			}
			if cap(tpm.PCRValues[pcrID][hashAlgo]) >= hasher.Size() {
				tpm.PCRValues[pcrID][hashAlgo] = tpm.PCRValues[pcrID][hashAlgo][:hasher.Size()]
				zeroSlice(tpm.PCRValues[pcrID][hashAlgo])
			} else {
				tpm.PCRValues[pcrID][hashAlgo] = make(Digest, hasher.Size())
			}
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

func zeroSlice[E any](s []E) {
	var zeroItem E
	for idx := range s {
		s[idx] = zeroItem
	}
}
