package amddata

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/amdbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

type PSPDirectory struct{}

var _ types.DataSource = (*PSPDirectory)(nil)

// Data implements types.DataSource.
func (PSPDirectory) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	amdAccessor, err := amdbiosimage.Get(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD data accessor: %w", err)
	}

	amdFW, err := amdAccessor.AMDFirmware()
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD Firmware structure: %w", err)
	}

	pspFW := amdFW.PSPFirmware()

	ranges := pkgbytes.Ranges{
		pspFW.PSPDirectoryLevel1Range,
		pspFW.PSPDirectoryLevel2Range,
	}
	addrMapper := biosimage.PhysMemMapper{}
	ranges = addrMapper.UnresolveFullImageOffset(amdAccessor.Image, ranges...)

	return types.NewReferenceData(&types.Reference{
		Artifact:      amdAccessor.Image,
		AddressMapper: addrMapper,
		Ranges:        ranges,
	}), nil
}

func (PSPDirectory) String() string {
	return "AMD_PSP_Directory"
}
