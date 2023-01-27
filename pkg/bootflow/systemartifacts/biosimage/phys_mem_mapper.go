package biosimage

import (
	"fmt"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// PhysMemMapper maps physical memory address space to a BIOS region of a system artifact BIOSImage.
type PhysMemMapper struct{}

// Resolve implements types.AddressMapper.
//
// It maps a physical memory address to an offset of the BIOS image.
func Resolve(artifact types.SystemArtifact, r pkgbytes.Range) (pkgbytes.Ranges, error) {
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
	biosRegion := biosRegions[0]

	return pkgbytes.Ranges{{
		Offset: r.Offset + artifact.Size() - 0x100000000 + biosRegion.Offset,
		Length: r.Length,
	}}, nil
}
