package amddata

import (
	"bytes"
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/amdbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/linuxboot/fiano/pkg/amd/manifest"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

type PSPVersion struct{}

var _ types.DataSource = (*PSPVersion)(nil)

// Data implements types.DataSource.
func (PSPVersion) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	amdAccessor, err := amdbiosimage.Get(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD data accessor: %w", err)
	}

	amdFW, err := amdAccessor.AMDFirmware()
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD Firmware structure: %w", err)
	}

	pspFW := amdFW.PSPFirmware()

	for _, pspDirectory := range []*manifest.PSPDirectoryTable{
		pspFW.PSPDirectoryLevel2,
		pspFW.PSPDirectoryLevel1,
	} {
		if pspDirectory == nil {
			continue
		}

		for _, entry := range pspDirectory.Entries {
			if entry.Type == manifest.PSPBootloaderFirmwareEntry {
				h, err := manifest.ParsePSPHeader(bytes.NewBuffer(amdAccessor.Image.Content[entry.LocationOrValue : entry.LocationOrValue+uint64(entry.Size)]))
				if err != nil {
					return nil, fmt.Errorf("failed to parse PSP bootloader header: %w", err)
				}

				ranges := pkgbytes.Ranges{{
					Offset: entry.LocationOrValue + h.VersionOffset(),
					Length: h.VersionLength(),
				}}
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
		}
	}

	return nil, fmt.Errorf("PSP version not found")
}

func (PSPVersion) String() string {
	return "AMD_PSP_Directory"
}
