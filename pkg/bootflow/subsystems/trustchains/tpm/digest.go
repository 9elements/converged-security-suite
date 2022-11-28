package tpm

import (
	"fmt"
)

// Digest is a digest/hash value
type Digest []byte

// String implements fmt.Stringer.
func (d Digest) String() string {
	return fmt.Sprintf("0x%X", []byte(d))
}
