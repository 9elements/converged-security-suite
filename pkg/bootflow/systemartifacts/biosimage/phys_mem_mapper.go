package biosimage

import (
	"fmt"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
)

// PhysMemMapper maps physical memory address space to a BIOS region of a system artifact BIOSImage.
type PhysMemMapper struct{}

// Resolve implements types.AddressMapper.
//
// It maps a physical memory address to an offset of the BIOS region.
func (PhysMemMapper) Resolve(artifact types.SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	biosRegion, err := getBIOSRegion(artifact)
	if err != nil {
		return nil, err
	}

	var result pkgbytes.Ranges
	for _, r := range ranges {
		result = append(result, pkgbytes.Range{
			Offset: r.Offset + biosRegion.Offset + artifact.Size() - 0x100000000,
			Length: r.Length,
		})
	}
	return result, nil
}

// Unresolve implements types.AddressMapper.
//
// It maps an offset of the BIOS region to a physical memory address.
func (PhysMemMapper) Unresolve(artifact types.SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	biosRegion, err := getBIOSRegion(artifact)
	if err != nil {
		return nil, err
	}

	var result pkgbytes.Ranges
	for _, r := range ranges {
		result = append(result, pkgbytes.Range{
			Offset: r.Offset + biosRegion.Offset + 0x100000000 - artifact.Size(),
			Length: r.Length,
		})
	}
	return result, nil
}

// UnresolveFullImageOffset is similar to Unresolve, but the offset is of the whole UEFI image,
// (while BIOS region is usually a component inside an UEFI image).
//
// It maps an offset of the UEFI image to a physical memory address.
func (PhysMemMapper) UnresolveFullImageOffset(artifact types.SystemArtifact, ranges ...pkgbytes.Range) pkgbytes.Ranges {
	result := make(pkgbytes.Ranges, 0, len(ranges))
	for _, r := range ranges {
		result = append(result, pkgbytes.Range{
			Offset: r.Offset + 0x100000000 - artifact.Size(),
			Length: r.Length,
		})
	}
	return result
}

func getBIOSRegion(artifact types.SystemArtifact) (*ffs.Node, error) {
	img, ok := artifact.(*BIOSImage)
	if !ok {
		return nil, fmt.Errorf("artifact %T is not a BIOSImage", artifact)
	}

	root, err := img.Parse()
	if err != nil {
		return nil, fmt.Errorf("unable to parse UEFI: %w", err)
	}

	biosRegions, err := root.GetByRegionType(uefi.RegionTypeBIOS)
	if err != nil {
		return nil, fmt.Errorf("unable to find the BIOS region: %w", err)
	}
	if len(biosRegions) != 1 {
		return nil, fmt.Errorf("expected exactly one BIOS region, but found %d", len(biosRegions))
	}

	return biosRegions[0], nil
}
