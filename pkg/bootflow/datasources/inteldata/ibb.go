package inteldata

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type IBB struct{}

var _ types.DataSource = (*IBB)(nil)

// Data implements types.DataSource.
func (IBB) Data(s *types.State) (*types.Data, error) {
	intelFW, err := intelbiosimage.Get(s)
	if err != nil {
		return nil, fmt.Errorf("unable to get Intel data accessor: %w", err)
	}

	bpm, _, err := intelFW.BootPolicyManifest()
	if err != nil {
		return nil, fmt.Errorf("unable to get BPM: %w", err)
	}

	ranges := bpm.IBBDataRanges(intelFW.SystemArtifact().Size())
	addrMapper := biosimage.PhysMemMapper{}
	ranges = addrMapper.UnresolveFullImageOffset(intelFW.SystemArtifact(), ranges...)
	return &types.Data{
		References: []types.Reference{{
			Artifact:      intelFW.SystemArtifact(),
			AddressMapper: addrMapper,
			Ranges:        ranges,
		}},
	}, nil
}

func (IBB) String() string {
	return "IBB"
}
