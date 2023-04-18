package datasources

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	"github.com/hashicorp/go-multierror"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/guid"
)

// UEFIGUIDFirst implements types.DataSource by referencing to the data defined
// by the UEFI objects of the specified set of GUID. If multiple GUIDs
// are provided, then they are being tried in the given order until
// the first non-empty or erroneous result.
type UEFIGUIDFirst []guid.GUID

var _ types.DataSource = (UEFIGUIDFirst)(nil)

// Data implements types.DataSource.
func (ds UEFIGUIDFirst) Data(_ context.Context, state *types.State) (*types.Data, error) {
	imgRaw, err := biosimage.Get(state)
	if err != nil {
		return nil, fmt.Errorf("unable to get BIOS Firmware: %w", err)
	}
	imgUEFI, err := imgRaw.Parse()
	if err != nil {
		return nil, fmt.Errorf("unable to parse the firmware image: %w", err)
	}

	addrMapper := biosimage.PhysMemMapper{}

	var (
		ranges pkgbytes.Ranges
		mErr   multierror.Error
	)
	for _, guid := range ds {
		err = (&ffs.NodeVisitor{
			Callback: func(node ffs.Node) (bool, error) {
				guidCmp := node.GUID()
				if guidCmp == nil || *guidCmp != guid {
					return true, nil
				}
				if node.Offset == math.MaxUint64 {
					// Was unable to detect the offset; it is expected
					// if the volume is in a compressed area.
					mErr.Errors = append(mErr.Errors, fmt.Errorf("unable to detect the offset of an UEFI volume %s", guid.String()))
					return true, nil
				}
				ranges = append(ranges, addrMapper.UnresolveFullImageOffset(imgRaw, node.Range)...)
				return true, nil
			},
			FallbackToContainerRange: true,
		}).Run(imgUEFI)
		if err != nil {
			return nil, fmt.Errorf("unable to get volumes with GUID '%s': %w", guid, err)
		}
		if len(ranges) > 0 {
			break
		}
	}
	if len(mErr.Errors) != 0 {
		return nil, mErr.ErrorOrNil()
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("no volumes with GUIDs %s found", ds.guids())
	}

	return types.NewReferenceData(&types.Reference{
		Artifact:      imgRaw,
		AddressMapper: addrMapper,
		Ranges:        ranges,
	}), nil
}

func (ds UEFIGUIDFirst) guids() string {
	var result []string
	for _, guid := range ds {
		result = append(result, guid.String())
	}
	return strings.Join(result, ", ")
}

// String implements fmt.Stringer.
func (ds UEFIGUIDFirst) String() string {
	return fmt.Sprintf("UEFIGUIDFirst(%s)", ds.guids())
}
