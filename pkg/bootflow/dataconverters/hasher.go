package dataconverters

import (
	"hash"
	"sync"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Hasher struct {
	Locker sync.Mutex
	Hash   hash.Hash
}

var _ types.DataConverter = (*Hasher)(nil)

func NewHasher(h hash.Hash) *Hasher {
	return &Hasher{
		Hash: h,
	}
}

func (h *Hasher) Convert(in types.RawBytes) types.ConvertedBytes {
	h.Locker.Lock()
	defer h.Locker.Unlock()
	h.Hash.Reset()
	h.Hash.Write(in)
	result := h.Hash.Sum(nil)
	return result
}

type HasherFactory struct {
	NewHasherFunc func() hash.Hash
}

var _ types.DataConverter = (*HasherFactory)(nil)
var _ types.DataConverterFactory = (*HasherFactory)(nil)

// NewHasherFactory returns a types.DataConverter using a hasher.
func NewHasherFactory(f func() hash.Hash) HasherFactory {
	return HasherFactory{
		NewHasherFunc: f,
	}
}

// Convert implements types.DataConverterFactory.
func (w HasherFactory) NewDataConverter() types.DataConverter {
	return &Hasher{
		Hash: w.NewHasherFunc(),
	}
}

// Convert implements types.DataConverter.
func (w HasherFactory) Convert(in types.RawBytes) types.ConvertedBytes {
	h := w.NewHasherFunc()
	h.Write(in)
	result := h.Sum(nil)
	return result
}
