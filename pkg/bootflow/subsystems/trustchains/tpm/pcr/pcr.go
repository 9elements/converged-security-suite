package pcr

import (
	"fmt"
)

// Values is a complete set of initialized PCR values of a TPM.
type Values [][]Digest

// ID is a numeric identifier of a PCR register. For example PCR0 has ID == 0 and PCR8 has ID == 8.
type ID uint8

func (id ID) String() string {
	return fmt.Sprintf("PCR%d", int(id))
}

// Get returns a PCR value given its index and hash algorithm.
func (s Values) Get(pcrID ID, hashAlg Algorithm) (Digest, error) {
	if len(s) <= int(pcrID) {
		return nil, fmt.Errorf("PCR %d is not initialized", pcrID)
	}
	if len(s[pcrID]) <= int(hashAlg) {
		return nil, fmt.Errorf("PCR %d:%s is not initialized", pcrID, hashAlg)
	}
	return s[pcrID][hashAlg], nil
}

// Set overrides a PCR value given its index and hash algorithm.
func (s Values) Set(pcrID ID, hashAlg Algorithm, value Digest) error {
	if len(s) <= int(pcrID) {
		return fmt.Errorf("PCR %d is not initialized", pcrID)
	}

	if len(s[pcrID]) <= int(hashAlg) {
		return fmt.Errorf("PCR %d:%s is not initialized", pcrID, hashAlg)
	}

	s[pcrID][hashAlg] = value
	return nil
}
