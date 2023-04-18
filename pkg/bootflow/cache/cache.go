package cache

// Cache is the storage of cached data.
type Cache interface {
	Get(k any) (any, bool)
	Set(k, v any)
	Reset()
}

// DummyCache is an implementation of Cache, which does not cache anything.
type DummyCache struct{}

var _ Cache = (*DummyCache)(nil)

func (DummyCache) Get(k any) (any, bool) {
	return nil, false
}

func (DummyCache) Set(k, v any) {}

func (DummyCache) Reset() {}
