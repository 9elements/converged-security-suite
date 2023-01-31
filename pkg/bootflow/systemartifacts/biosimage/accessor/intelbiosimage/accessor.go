package intelbiosimage

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Accessor struct {
	Image *biosimage.BIOSImage
	Cache types.Cache
}

func (a *Accessor) Init(img *biosimage.BIOSImage, cache types.Cache) {
	a.Image = img
	a.Cache = cache
}

func (a *Accessor) SystemArtifact() *biosimage.BIOSImage {
	return a.Image
}

func Get(s *types.State) (*Accessor, error) {
	return accessor.GetOrCreate[Accessor, *Accessor](s)
}
