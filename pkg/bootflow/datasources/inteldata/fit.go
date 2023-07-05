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
			offset := fitEntry.GetEntryBase().Headers.Address.Pointer()
			length := len(fitEntry.GetEntryBase().DataSegmentBytes)

			return types.NewData(&types.Reference{
				Artifact: biosFW,
				MappedRanges: types.MappedRanges{
					AddressMapper: biosimage.PhysMemMapper{},
					Ranges: pkgbytes.Ranges{{
						Offset: offset,
						Length: uint64(length),
					}},
				},
			}), nil
		}
	}

	return nil, fmt.Errorf("unable to find FIT entry of type %s", fit.EntryType(d))
}

// String implements fmt.Stringer.
func (d FITFirst) String() string {
	return fmt.Sprintf("IntelFITFirst(%s)", fit.EntryType(d))
}

// FITAll implements DataSource by referencing to the data defined
// by the all FIT entries of the specified type.
type FITAll fit.EntryType

var _ types.DataSource = (FITAll)(0)

// Data implements types.DataSource.
func (d FITAll) Data(_ context.Context, state *types.State) (*types.Data, error) {
	biosFW, err := biosimage.Get(state)
	if err != nil {
		return nil, fmt.Errorf("unable to get BIOS image: %w", err)
	}
	fitEntries, err := fit.GetEntries(biosFW.Content)
	if err != nil {
		return nil, fmt.Errorf("unable to parse FIT table: %w", err)
	}

	ref := &types.Reference{
		Artifact: biosFW,
		MappedRanges: types.MappedRanges{
			AddressMapper: biosimage.PhysMemMapper{},
			Ranges:        []pkgbytes.Range{},
		},
	}
	for _, fitEntry := range fitEntries {
		if fitEntry.GetEntryBase().Headers.Type() == fit.EntryType(d) {
			offset := fitEntry.GetEntryBase().Headers.Address.Pointer()
			length := len(fitEntry.GetEntryBase().DataSegmentBytes)

			ref.Ranges = append(ref.Ranges, pkgbytes.Range{
				Offset: offset,
				Length: uint64(length),
			})
		}
	}

	return types.NewData(ref), nil
}

// String implements fmt.Stringer.
func (d FITAll) String() string {
	return fmt.Sprintf("IntelFITAll(%s)", fit.EntryType(d))
}
