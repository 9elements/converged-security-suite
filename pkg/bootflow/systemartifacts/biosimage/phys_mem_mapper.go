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
// It maps a physical memory address to an offset inside the system artifact (UEFI image).
func (t PhysMemMapper) Resolve(artifact types.SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	return t.ResolveFullImageOffset(artifact, ranges...), nil
}

// ResolveFullImageOffset maps a physical memory address to an offset inside the system artifact (UEFI image).
func (PhysMemMapper) ResolveFullImageOffset(artifact types.SystemArtifact, ranges ...pkgbytes.Range) pkgbytes.Ranges {
	var result pkgbytes.Ranges
	for _, r := range ranges {
		result = append(result, pkgbytes.Range{
			Offset: r.Offset - 0x100000000 + artifact.Size(),
			Length: r.Length,
		})
	}
	return result
}

// Unresolve implements types.AddressMapper.
//
// It maps an offset of the UEFI image to a physical memory address.
func (t PhysMemMapper) Unresolve(artifact types.SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	return t.UnresolveFullImageOffset(artifact, ranges...), nil
}

// UnresolveFullImageOffset maps an offset of the UEFI image to a physical memory address.
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

// ResolveBIOSRegionOffset is similar to Resolve, but the given
// offsets are based on BIOS region instead of the whole UEFI image.
//
// It maps a physical memory address to an offset inside the system artifact (UEFI image).
func (PhysMemMapper) ResolveBIOSRegionOffset(artifact types.SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	biosRegion, err := getBIOSRegion(artifact)
	if err != nil {
		return nil, err
	}

	var result pkgbytes.Ranges
	for _, r := range ranges {
		result = append(result, pkgbytes.Range{
			Offset: r.Offset + biosRegion.Length - 0x100000000,
			Length: r.Length,
		})
	}
	return result, nil
}

// UnresolveBIOSRegionOffset is similar to Unresolve, but the given
// offsets are based on BIOS region instead of the whole UEFI image.
//
// It maps an offset of the BIOS region to a physical memory address.
func (PhysMemMapper) UnresolveBIOSRegionOffset(artifact types.SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	biosRegion, err := getBIOSRegion(artifact)
	if err != nil {
		return nil, err
	}

	var result pkgbytes.Ranges
	for _, r := range ranges {
		result = append(result, pkgbytes.Range{
			Offset: r.Offset - biosRegion.Length + 0x100000000,
			Length: r.Length,
		})
	}
	return result, nil
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
