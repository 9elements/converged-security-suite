package amddata

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/amdbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

type BIOSDirectory struct{}

var _ types.DataSource = (*BIOSDirectory)(nil)

// Data implements types.DataSource.
func (BIOSDirectory) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	amdAccessor, err := amdbiosimage.Get(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD data accessor: %w", err)
	}

	amdFW, err := amdAccessor.AMDFirmware()
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD Firmware structure: %w", err)
	}

	pspFW := amdFW.PSPFirmware()

	headerSizeL1 := uint64(binary.Size(pspFW.BIOSDirectoryLevel1.BIOSDirectoryTableHeader))
	headerSizeL2 := uint64(binary.Size(pspFW.BIOSDirectoryLevel2.BIOSDirectoryTableHeader))
	ranges := pkgbytes.Ranges{
		pkgbytes.Range{
			Offset: pspFW.BIOSDirectoryLevel1Range.Offset,
			Length: headerSizeL1,
		},
		pkgbytes.Range{
			Offset: pspFW.BIOSDirectoryLevel1Range.Offset + headerSizeL1,
			Length: pspFW.BIOSDirectoryLevel1Range.Length - headerSizeL1,
		},
		pkgbytes.Range{
			Offset: pspFW.BIOSDirectoryLevel2Range.Offset,
			Length: headerSizeL2,
		},
		pkgbytes.Range{
			Offset: pspFW.BIOSDirectoryLevel2Range.Offset + headerSizeL2,
			Length: pspFW.BIOSDirectoryLevel2Range.Length - headerSizeL2,
		},
	}
	addrMapper := biosimage.PhysMemMapper{}
	ranges = addrMapper.UnresolveFullImageOffset(amdAccessor.Image, ranges...)

	return types.NewData(&types.Reference{
		Artifact: amdAccessor.Image,
		MappedRanges: types.MappedRanges{
			AddressMapper: addrMapper,
			Ranges:        ranges,
		},
	}), nil
}

func (BIOSDirectory) String() string {
	return "AMD_BIOS_Directory"
}
