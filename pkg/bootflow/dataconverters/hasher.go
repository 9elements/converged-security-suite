package dataconverters

import (
	"hash"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type hasher struct {
	hash.Hash
}

var _ types.DataConverter = (*hasher)(nil)

// Hasher returns a types.DataConverter using a hasher.
func Hasher(h hash.Hash) hasher {
	h.Reset()
	return hasher{
		Hash: h,
	}
}

// Convert implements types.DataConverter.
func (h hasher) Convert(in types.RawBytes) types.ConvertedBytes {
	h.Write(in)
	result := h.Sum(nil)
	h.Reset()
	return result
}
