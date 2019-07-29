package api

import (
	"io"

	tpm1 "github.com/google/go-tpm/tpm"
)

func NVReadAll(conn io.ReadWriteCloser, index uint32) []byte {
	ret := []byte{}

	for i := uint32(0); ; i += 1 {
		b, err := tpm1.NVReadValueNoAuth(conn, index, i, 1)
		if err != nil {
			return ret
		}
		ret = append(ret, b[0])
	}
}
