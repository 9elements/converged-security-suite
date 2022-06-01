package tpm

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/google/go-tpm/tpm2"
)

const (
	// currently we support only PCR0 and PCR1
	PCRRegistersAmount = 2
)

var _ types.TrustChain = (*TPM)(nil)

type TPM struct {
	PCRValues  PCRValues
	CommandLog CommandLog
	EventLog   EventLog
}

func NewTPM() *TPM {
	return &TPM{}
}

func SupportedHashAlgos() []tpm2.Algorithm {
	return []tpm2.Algorithm{
		tpm2.AlgSHA1,
		tpm2.AlgSHA256,
	}
}

var tpmMaxHashAlgo tpm2.Algorithm

func init() {
	supportedAlgos := SupportedHashAlgos()
	tpmMaxHashAlgo = supportedAlgos[0]
	for _, algo := range supportedAlgos {
		if algo > tpmMaxHashAlgo {
			tpmMaxHashAlgo = algo
		}
	}
}

func StateExec(state *types.State, fn func(tpm *TPM) error) error {
	return state.TrustChainExec((*TPM)(nil), func(trustChain types.TrustChain) error {
		return fn(trustChain.(*TPM))
	})
}

func (chain *TPM) IsInitialized() bool {
	return len(chain.PCRValues) > 0
}

func (chain *TPM) TPMInit(locality uint8) error {
	chain.CommandLog = append(chain.CommandLog, CommandLogEntryInit{
		Locality: locality,
	})

	chain.PCRValues = make(PCRValues, PCRRegistersAmount)

	supportedAlgos := SupportedHashAlgos()
	for _, hashAlgo := range supportedAlgos {
		h, err := hashAlgo.Hash()
		if err != nil {
			return fmt.Errorf("unable to initialize a hasher factory for hash algo %v", hashAlgo)
		}
		hasher := h.New()
		for pcrID := PCRID(0); pcrID < PCRRegistersAmount; pcrID++ {
			if chain.PCRValues[pcrID] == nil {
				chain.PCRValues[pcrID] = make([][]byte, tpmMaxHashAlgo+1)
			}
			chain.PCRValues[pcrID][hashAlgo] = make([]byte, hasher.Size())
			pcrValue := chain.PCRValues[pcrID][hashAlgo]
			switch pcrID {
			case 0:
				pcrValue[len(pcrValue)-1] = locality
			case 1:
			default:
				return fmt.Errorf("unexpected PCR ID: %d", pcrID)
			}
		}
	}
	return nil
}

func (chain *TPM) TPMExtend(pcrIndex PCRID, hashAlgo tpm2.Algorithm, digest []byte) error {
	chain.CommandLog = append(chain.CommandLog, CommandLogEntryExtend{
		PCRIndex: pcrIndex,
		HashAlgo: hashAlgo,
		Digest:   digest,
	})

	h, err := hashAlgo.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash algo: %w", err)
	}
	hasher := h.New()

	oldValue, err := chain.PCRValues.Get(pcrIndex, hashAlgo)
	if err != nil {
		return fmt.Errorf("unable to get the PCR value: %w", err)
	}
	if _, err := hasher.Write(oldValue); err != nil {
		return fmt.Errorf("unable to write into hasher %T the original value: %w", hasher, err)
	}
	if _, err := hasher.Write(digest); err != nil {
		return fmt.Errorf("unable to write into hasher %T the given value: %w", hasher, err)
	}
	newValue := hasher.Sum(nil)
	if err := chain.PCRValues.Set(pcrIndex, hashAlgo, newValue); err != nil {
		return fmt.Errorf("unable to update the PCR value: %w", err)
	}
	return nil
}

func (chain *TPM) TPMEventLogAdd(pcrIndex PCRID, hashAlgo tpm2.Algorithm, digest, data []byte) error {
	chain.EventLog.Add(pcrIndex, hashAlgo, digest, data)
	return nil
}

type PCRValues [][][]byte

type PCRID = pcrtypes.ID

func (s PCRValues) Get(pcrID PCRID, hashAlg tpm2.Algorithm) ([]byte, error) {
	if len(s) <= int(pcrID) {
		return nil, fmt.Errorf("PCR %d is not initialized", pcrID)
	}
	if len(s[pcrID]) <= int(hashAlg) {
		return nil, fmt.Errorf("PCR %d:%s is not initialized", pcrID, hashAlg)
	}
	return s[pcrID][hashAlg], nil
}

func (s PCRValues) Set(pcrID PCRID, hashAlg tpm2.Algorithm, value []byte) error {
	if hashAlg > tpmMaxHashAlgo {
		panic(fmt.Errorf("too high value of hash algo: %d > %d", hashAlg, tpm2.AlgSHA3_512))
	}

	if len(s) <= int(pcrID) {
		return fmt.Errorf("PCR %d is not initialized", pcrID)
	}

	if len(s[pcrID]) <= int(hashAlg) {
		return fmt.Errorf("PCR %d:%s is not initialized", pcrID, hashAlg)
	}

	s[pcrID][hashAlg] = value
	return nil
}
