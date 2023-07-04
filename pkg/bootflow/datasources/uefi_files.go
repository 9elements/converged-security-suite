package datasources

import (
	"context"
	"fmt"
	"math"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	"github.com/hashicorp/go-multierror"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// UEFIFiles implements types.DataSource by referencing to the files
// in the UEFI layout which has types from the given list.
type UEFIFiles func(*uefi.File) (bool, error)

var _ types.DataSource = (UEFIFiles)(nil)

// Data implements types.DataSource.
func (ds UEFIFiles) Data(_ context.Context, state *types.State) (*types.Data, error) {
	imgRaw, err := biosimage.Get(state)
	if err != nil {
		return nil, fmt.Errorf("unable to get BIOS Firmware: %w", err)
	}
	imgUEFI, err := imgRaw.Parse()
	if err != nil {
		return nil, fmt.Errorf("unable to parse the firmware image: %w", err)
	}

	var found []ffs.Node
	visitor := &ffs.NodeVisitor{
		Callback: func(node ffs.Node) (bool, error) {
			file, ok := node.Firmware.(*uefi.File)
			if !ok {
				return true, nil
			}

			match, err := ds(file)
			if err != nil {
				return true, fmt.Errorf("the Callback function return error: %w", err)
			}
			if match {
				found = append(found, node)
			}
			return true, nil
		},
		FallbackToContainerRange: true,
	}
	if err := visitor.Run(imgUEFI); err != nil {
		return nil, fmt.Errorf("unable to traverse the UEFI layout: %w", err)
	}

	addrMapper := biosimage.PhysMemMapper{}

	var (
		ranges pkgbytes.Ranges
		mErr   multierror.Error
	)
	for _, node := range found {
		file := node.Firmware.(*uefi.File)
		if node.Offset == math.MaxUint64 {
			// Was unable to detect the offset; it is expected
			// if the volume is in a compressed area.
			mErr.Errors = append(mErr.Errors, fmt.Errorf("unable to detect the offset of file: %#+v", file))
			continue
		}
		fRanges := addrMapper.UnresolveFullImageOffset(imgRaw, node.Range)
		ranges = append(ranges, fRanges...)
	}
	if len(mErr.Errors) != 0 {
		return nil, mErr.ErrorOrNil()
	}
	ranges.SortAndMerge()
	if len(ranges) == 0 {
		return &types.Data{}, nil
	}

	return types.NewData(&types.Reference{
		Artifact: imgRaw,
		MappedRanges: types.MappedRanges{
			AddressMapper: addrMapper,
			Ranges:        ranges,
		},
	}), nil
}
