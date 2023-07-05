package tpm

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
)

// PCRValues is a complete set of initialized PCR values of a TPM.
type PCRValues = pcr.Values

// PCRID is a numeric identifier of a PCR register. For example PCR0 has ID == 0 and PCR8 has ID == 8.
type PCRID = pcr.ID

// Digest is a digest/hash value
type Digest = pcr.Digest
