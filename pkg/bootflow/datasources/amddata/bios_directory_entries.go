package amddata

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/amdbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/amd/manifest"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

type BIOSDirectoryEntriesType struct {
	EntryTypes []manifest.BIOSDirectoryTableEntryType
	Level      amdbiosimage.DirectoryLevel
}

func BIOSDirectoryEntries(levels amdbiosimage.DirectoryLevel, entryTypes ...manifest.BIOSDirectoryTableEntryType) BIOSDirectoryEntriesType {
	return BIOSDirectoryEntriesType{
		EntryTypes: entryTypes,
		Level:      levels,
	}
}

var _ types.DataSource = (*BIOSDirectoryEntriesType)(nil)

// Data implements types.DataSource.
func (selector BIOSDirectoryEntriesType) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	amdAccessor, err := amdbiosimage.Get(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD data accessor: %w", err)
	}

	var ranges pkgbytes.Ranges
	entries, err := amdAccessor.BIOSDirectoryEntries(selector.Level, selector.EntryTypes...)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		ranges = append(ranges, pkgbytes.Range{
			Offset: entry.SourceAddress,
			Length: uint64(entry.Size),
		})
	}

	addrMapper := biosimage.PhysMemMapper{}
	ranges = addrMapper.UnresolveFullImageOffset(amdAccessor.Image, ranges...)

	return types.NewReferenceData(&types.Reference{
		Artifact:      amdAccessor.Image,
		AddressMapper: addrMapper,
		Ranges:        ranges,
	}), nil
}

func (selector BIOSDirectoryEntriesType) String() string {
	return fmt.Sprintf("BIOSDirectoryEntries{L: %s, T: %#+v}", selector.Level, selector.EntryTypes)
}
