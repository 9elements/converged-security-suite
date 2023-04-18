package datasources

import (
	"context"
	"fmt"
	"math"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/uefi"
)

type VolumeOfType struct {
	types.DataSource
}

func VolumeOf(ds types.DataSource) VolumeOfType {
	return VolumeOfType{
		DataSource: ds,
	}
}

var _ types.DataSource = (*VolumeOfType)(nil)

// Data implements types.DataSource.
func (v VolumeOfType) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	biosImg, err := biosimage.Get(s)
	if err != nil {
		return nil, fmt.Errorf("BIOS image artifact is not available: %w", err)
	}

	uefiImg, err := biosImg.Parse()
	if err != nil {
		return nil, fmt.Errorf("unable to parse the UEFI image: %w", err)
	}

	d, err := v.DataSource.Data(ctx, s)
	if err != nil {
		return nil, err
	}

	if d.ForcedBytes() != nil {
		return nil, fmt.Errorf("data source VolumeOf does not support ForcedBytes")
	}
	if d.Converter != nil {
		return nil, fmt.Errorf("data source VolumeOf does not support Converter")
	}

	var ranges pkgbytes.Ranges
	for _, ref := range d.References() {
		if ref.Artifact != biosImg {
			return nil, fmt.Errorf("reference %s is not referencing to the BIOSImage", format.NiceString(ref))
		}
		ranges, err := ref.ResolvedRanges()
		if err != nil {
			return nil, fmt.Errorf("unable to get resolve data ranges: %w", err)
		}

		for _, r := range ranges {
			nodes, err := uefiImg.GetByRange(r)
			if err != nil {
				return nil, fmt.Errorf("unable to get nodes by range %#+v: %w", r, err)
			}

			var volume *ffs.Node
			for _, node := range nodes {
				if node.Range.Offset == math.MaxUint64 {
					continue
				}
				if _, ok := node.Firmware.(*uefi.FirmwareVolume); ok {
					volume = node
					break
				}
			}
			if volume == nil {
				return nil, fmt.Errorf("unable to find the volume for reference: %s (range: %X:%X)", format.NiceString(ref), r.Offset, r.End())
			}
			ranges = append(ranges, volume.Range)
		}
	}

	ranges.SortAndMerge()
	if len(ranges) == 0 {
		return &types.Data{}, nil
	}

	addrMapper := biosimage.PhysMemMapper{}
	ranges = addrMapper.UnresolveFullImageOffset(biosImg, ranges...)
	return types.NewReferenceData(&types.Reference{
		Artifact:      biosImg,
		AddressMapper: addrMapper,
		Ranges:        ranges,
	}), nil
}
