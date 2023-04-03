package amddata

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/amdbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

type EmbeddedFirmware struct{}

var _ types.DataSource = (*EmbeddedFirmware)(nil)

// Data implements types.DataSource.
func (EmbeddedFirmware) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	amdAccessor, err := amdbiosimage.Get(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD data accessor: %w", err)
	}

	amdFW, err := amdAccessor.AMDFirmware()
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD Firmware structure: %w", err)
	}
	pspFW := amdFW.PSPFirmware()

	ranges := pkgbytes.Ranges{pspFW.EmbeddedFirmwareRange}
	addrMapper := biosimage.PhysMemMapper{}
	ranges = addrMapper.UnresolveFullImageOffset(amdAccessor.Image, ranges...)

	return types.NewReferenceData(&types.Reference{
		Artifact:      amdAccessor.Image,
		AddressMapper: addrMapper,
		Ranges:        ranges,
	}), nil
}

func (EmbeddedFirmware) String() string {
	return "EmbeddedFirmware"
}
