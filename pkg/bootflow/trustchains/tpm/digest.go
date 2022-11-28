package tpm

import "fmt"

type Digest []byte

func (d Digest) String() string {
	return fmt.Sprintf("0x%X", []byte(d))
}
