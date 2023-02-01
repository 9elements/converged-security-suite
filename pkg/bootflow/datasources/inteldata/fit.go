package inteldata

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// FITFirst implements DataSource by referencing to the data defined
// by the first FIT entry of the specified type.
type FITFirst fit.EntryType

var _ types.DataSource = (FITFirst)(0)

// Data implements types.DataSource.
func (d FITFirst) Data(_ context.Context, state *types.State) (*types.Data, error) {
	biosFW, err := biosimage.Get(state)
	if err != nil {
		return nil, fmt.Errorf("unable to get BIOS image: %w", err)
	}
	fitEntries, err := fit.GetEntries(biosFW.Content)
	if err != nil {
		return nil, fmt.Errorf("unable to parse FIT table: %w", err)
	}

	for _, fitEntry := range fitEntries {
		if fitEntry.GetEntryBase().Headers.Type() == fit.EntryType(d) {
			offset := fitEntry.GetEntryBase().Headers.Address.Offset(uint64(len(biosFW.Content)))
			length := len(fitEntry.GetEntryBase().DataSegmentBytes)
			ranges := pkgbytes.Ranges{{
				Offset: offset,
				Length: uint64(length),
			}}
			addrMapper := biosimage.PhysMemMapper{}
			ranges = addrMapper.UnresolveFullImageOffset(biosFW, ranges...)
			data := &types.Data{
				References: []types.Reference{{
					Artifact:      biosFW,
					AddressMapper: addrMapper,
					Ranges:        ranges,
				}},
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("unable to find FIT entry of type %s", fit.EntryType(d))
}

// String implements fmt.Stringer.
func (d FITFirst) String() string {
	return fmt.Sprintf("IntelFITFirst(%s)", fit.EntryType(d))
}
