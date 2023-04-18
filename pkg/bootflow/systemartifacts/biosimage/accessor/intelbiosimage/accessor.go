package intelbiosimage

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/cache"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// Accessor is the accessor of Intel-specific data from a BIOS region
type Accessor struct {
	Image *biosimage.BIOSImage
	Cache cache.Cache
}

// Init implements accessor.Accessor.
func (a *Accessor) Init(img *biosimage.BIOSImage, cache cache.Cache) {
	a.Image = img
	a.Cache = cache
}

// Init implements accessor.Accessor.
func (a *Accessor) SystemArtifact() *biosimage.BIOSImage {
	return a.Image
}

// Get returns an Accessor from the State (and lazily creates one if it is not created).
func Get(ctx context.Context, s *types.State) (*Accessor, error) {
	return accessor.GetOrCreate[Accessor](ctx, s)
}
