package datasources

import (
	"fmt"
	"math"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosfirmware"
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
	err := biosfirmware.FromState(state, func(fwRaw *biosfirmware.BIOSFirmware) error {
		firmware, err := fwRaw.Parse()
		if err != nil {
			return fmt.Errorf("unable to parse the firmware image: %w", err)
		}

		var volumes []*ffs.Node
		for _, guid := range ds {
			volumes, err = firmware.GetByGUID(guid)
			if err != nil {
				return fmt.Errorf("unable to get volumes with GUID '%s': %w", guid, err)
			}
			if len(volumes) > 0 {
				break
			}
		}
		if len(volumes) == 0 {
			return fmt.Errorf("no volumes with GUIDs %#+v found", ds)
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
			return mErr.ErrorOrNil()
		}

		data = &types.Data{
			References: []types.Reference{{
				Artifact: fwRaw,
				Ranges:   ranges,
			}},
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to extract an UEFI volume with GUIDs %+v: %w", ds, err)
	}
	return data, nil
}
