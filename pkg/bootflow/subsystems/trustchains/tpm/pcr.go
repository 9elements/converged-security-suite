package tpm

import (
	"fmt"

	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/google/go-tpm/tpm2"
)

// PCRValues is a complete set of initialized PCR values of a TPM.
type PCRValues [][][]byte

// PCRID is a PCR index.
type PCRID = pcrtypes.ID

// Get returns a PCR value given its index and hash algorithm.
func (s PCRValues) Get(pcrID PCRID, hashAlg tpm2.Algorithm) ([]byte, error) {
	if len(s) <= int(pcrID) {
		return nil, fmt.Errorf("PCR %d is not initialized", pcrID)
	}
	if len(s[pcrID]) <= int(hashAlg) {
		return nil, fmt.Errorf("PCR %d:%s is not initialized", pcrID, hashAlg)
	}
	return s[pcrID][hashAlg], nil
}

// Set overrides a PCR value given its index and hash algorithm.
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
