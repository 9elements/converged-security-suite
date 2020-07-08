package hwapi

import (
	"io"

	tpm1 "github.com/google/go-tpm/tpm"
)

//NVReadAll returns the contents of the TPM NVRAM index
func (t TxtAPI) NVReadAll(conn io.ReadWriteCloser, index uint32) []byte {
	ret := []byte{}

	for i := uint32(0); ; i++ {
		b, err := tpm1.NVReadValue(conn, index, i, 1, nil)
		if err != nil {
			return ret
		}
		ret = append(ret, b[0])
	}
}
