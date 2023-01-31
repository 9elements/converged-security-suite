package dataconverters

import "hash"

type hasher struct {
	hash.Hash
}

func Hasher(h hash.Hash) hasher {
	return hasher{
		Hash: h,
	}
}

func (h hasher) Convert(in []byte) []byte {
	h.Reset()
	h.Write(in)
	result := h.Sum(nil)
	h.Reset()
	return result
}
