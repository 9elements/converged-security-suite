package amdbiosimage

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor"
	"github.com/linuxboot/fiano/pkg/amd/manifest"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

func (a *Accessor) AMDFirmware() (*manifest.AMDFirmware, error) {
	result := accessor.Memoize(a.Cache, func() (result struct {
		amdFW *manifest.AMDFirmware
		err   error
	}) {
		result.amdFW, result.err = manifest.NewAMDFirmware(amdImgWrapper{Image: a.Image})
		return
	})

	return result.amdFW, result.err
}

type amdImgWrapper struct {
	Image *biosimage.BIOSImage
}

func (w amdImgWrapper) ImageBytes() []byte {
	return w.Image.Content
}

func (w amdImgWrapper) PhysAddrToOffset(physAddr uint64) uint64 {
	resolvedSlice := (biosimage.PhysMemMapper{}).ResolveFullImageOffset(w.Image, pkgbytes.Range{
		Offset: physAddr,
		Length: 1,
	})
	if len(resolvedSlice) != 1 {
		panic(fmt.Errorf("supposed to be impossible: %d", len(resolvedSlice)))
	}
	resolved := resolvedSlice[0]
	return resolved.Offset
}

func (w amdImgWrapper) OffsetToPhysAddr(offset uint64) uint64 {
	resolvedSlice := (biosimage.PhysMemMapper{}).UnresolveFullImageOffset(w.Image, pkgbytes.Range{
		Offset: offset,
		Length: 1,
	})
	if len(resolvedSlice) != 1 {
		panic(fmt.Errorf("supposed to be impossible: %d", len(resolvedSlice)))
	}
	resolved := resolvedSlice[0]
	return resolved.Offset
}
