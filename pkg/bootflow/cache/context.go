package cache

import "context"

type ctxCacheKeyT struct{}

var ctxCacheKey = ctxCacheKeyT{}

// FromCtx extracts a Cache implementation from the context,
// if one is not defined then returns a dummy implementation.
func FromCtx(ctx context.Context) Cache {
	if cache, ok := ctx.Value(ctxCacheKey).(Cache); ok {
		return cache
	}

	return DummyCache{}
}

// CtxWithCache returns a context derivative with the Cache implementation
// set to the given one.
func CtxWithCache(ctx context.Context, cache Cache) context.Context {
	return context.WithValue(ctx, ctxCacheKey, cache)
}
