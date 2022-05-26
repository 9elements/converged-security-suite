package trustchains

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/google/go-tpm/tpm2"
)

var _ types.TrustChain = (*TPM)(nil)

type TPM struct {
	PCRValues PCRValues
	EventLog  TPMEventLog
}

func TPMFunc(state *types.State, fn func(tpm *TPM) error) error {
	for _, trustChain := range state.TrustChains {
		if tpm, ok := trustChain.(*TPM); ok {
			return fn(tpm)
		}
	}

	return fmt.Errorf("unable to find a trust chain backed by TPM")
}

func (chain *TPM) IsInitialized() bool {
	return len(chain.PCRValues) > 0
}

func (chain *TPM) TPMExtend(pcrIndex PCRID, hashAlgo tpm2.Algorithm, digest []byte) error {
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
	if hashAlg > tpm2.AlgSHA3_512 {
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

type TPMEventLog []TPMEventLogEntry

type TPMEventLogEntry struct {
	PCRIndex PCRID
	HashAlgo tpm2.Algorithm
	Digest   []byte
	Data     []byte
}

func (log *TPMEventLog) Add(pcrIndex PCRID, hashAlgo tpm2.Algorithm, digest, data []byte) {
	*log = append(*log, TPMEventLogEntry{
		PCRIndex: pcrIndex,
		HashAlgo: hashAlgo,
		Digest:   digest,
		Data:     data,
	})
}
