package tpm

import (
	"hash"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
)

var hasherPools = [0xffff]sync.Pool{}

type hasher struct {
	hash.Hash
	Algo tpm2.Algorithm
}

func acquireHasher(algo tpm2.Algorithm) (*hasher, error) {
	pool := &hasherPools[algo]

	r := pool.Get()
	if r != nil {
		return r.(*hasher), nil
	}

	h, err := algo.Hash()
	if err != nil {
		return nil, err
	}

	return &hasher{
		Hash: h.New(),
		Algo: algo,
	}, nil
}

func releaseHasher(hasher *hasher) {
	hasher.Hash.Reset()
	hasherPools[hasher.Algo].Put(hasher)
}
