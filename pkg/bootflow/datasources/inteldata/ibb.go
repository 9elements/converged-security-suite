package inteldata

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	bootpolicy "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/bootpolicy"
)

// IBB implements types.DataSource by referencing to
// the initial boot block.
type IBB struct{}

var _ types.DataSource = (*IBB)(nil)

// Data implements types.DataSource.
func (IBB) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	intelFW, err := intelbiosimage.Get(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("unable to get Intel data accessor: %w", err)
	}

	bpm, _, err := intelFW.BootPolicyManifest()
	if err != nil {
		return nil, fmt.Errorf("unable to get BPM: %w", err)
	}

	var ranges pkgbytes.Ranges
	bpmP := *bpm

	if bpmBg, ok := bpmP.(*bootpolicy.ManifestBG); ok {
		ranges = bpmBg.IBBDataRanges(intelFW.SystemArtifact().Size())
	}

	if bpmCBnt, ok := bpmP.(*bootpolicy.ManifestCBnT); ok {
		ranges = bpmCBnt.IBBDataRanges(intelFW.SystemArtifact().Size())
	}

	addrMapper := biosimage.PhysMemMapper{}
	ranges = addrMapper.UnresolveFullImageOffset(intelFW.SystemArtifact(), ranges...)

	return types.NewData(&types.Reference{
		Artifact: intelFW.SystemArtifact(),
		MappedRanges: types.MappedRanges{
			AddressMapper: addrMapper,
			Ranges:        ranges,
		},
	}), nil
}

func (IBB) String() string {
	return "IBB"
}
