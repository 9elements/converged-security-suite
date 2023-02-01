package accessor

import (
	"context"
	"fmt"
	"reflect"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/cache"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// Accessor is an abstract data accessor of implementation-specific data.
type Accessor[T any] interface {
	SystemArtifact() *biosimage.BIOSImage
	Init(img *biosimage.BIOSImage, cache cache.Cache)

	*T
}

func getOrCreateFromImage[T any, A Accessor[T]](img *biosimage.BIOSImage, c cache.Cache) *T {
	var newAccessor T
	if accessor, ok := img.Accessors[reflect.TypeOf(newAccessor)]; ok {
		return accessor.(*T)
	}

	if c == nil {
		c = cache.DummyCache{}
	}
	A(&newAccessor).Init(img, c)
	return &newAccessor
}

// GetOrCreate gets an Accessor or creates one (and sets to the State) if
// one wasn't set.
func GetOrCreate[T any, A Accessor[T]](ctx context.Context, s *types.State) (*T, error) {
	img, err := biosimage.Get(s)
	if err != nil {
		return nil, fmt.Errorf("unable to get BIOS image: %w", nil)
	}

	return getOrCreateFromImage[T, A](img, cache.FromCtx(ctx)), nil
}

// Memoize caches the result of a function and reuses it on a next call.
func Memoize[R any](c cache.Cache, calculate func() R) R {
	var zeroResult R
	if result, ok := c.Get(zeroResult); ok {
		return result.(R)
	}

	result := calculate()
	c.Set(zeroResult, result)
	return result
}
