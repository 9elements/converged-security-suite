package datasources

import (
	"fmt"
	"math"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	"github.com/hashicorp/go-multierror"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/guid"
)

type UEFIGUIDFirst []guid.GUID

var _ types.DataSource = (UEFIGUIDFirst)(nil)

func (ds UEFIGUIDFirst) Data(state *types.State) (*types.Data, error) {
	var data *types.Data
	imgRaw, err := biosimage.Get(state)
	if err != nil {
		return nil, fmt.Errorf("unable to get BIOS Firmware: %w", err)
	}
	imgUEFI, err := imgRaw.Parse()
	if err != nil {
		return nil, fmt.Errorf("unable to parse the firmware image: %w", err)
	}

	var volumes []*ffs.Node
	for _, guid := range ds {
		volumes, err = imgUEFI.GetByGUID(guid)
		if err != nil {
			return nil, fmt.Errorf("unable to get volumes with GUID '%s': %w", guid, err)
		}
		if len(volumes) > 0 {
			break
		}
	}
	if len(volumes) == 0 {
		return nil, fmt.Errorf("no volumes with GUIDs %#+v found", ds)
	}

	var (
		ranges pkgbytes.Ranges
		mErr   multierror.Error
	)
	for _, volume := range volumes {
		if volume.Offset == math.MaxUint64 {
			// Was unable to detect the offset; it is expected
			// if the volume is in a compressed area.
			mErr.Errors = append(mErr.Errors, fmt.Errorf("unable to detect the offset of a DXE volume"))
			continue
		}
		ranges = append(ranges, volume.Range)
	}
	if len(ranges) == 0 {
		return nil, mErr.ErrorOrNil()
	}

	data = &types.Data{
		References: []types.Reference{{
			Artifact: imgRaw,
			Ranges:   ranges,
		}},
	}
	return data, nil
}
