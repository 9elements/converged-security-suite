package datasources

import (
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

// MemRanges implements types.DataSource as a list of ranges in the physical memory address space.
type MemRanges pkgbytes.Ranges

var _ types.DataSource = (MemRanges)(nil)

// Data implements types.DataSource.
func (mrs MemRanges) Data(state *types.State) (*types.Data, error) {
	biosImg, err := biosimage.Get(state)
	if err != nil {
		return nil, fmt.Errorf("unable to find where the memory ranges are mapped to; BIOS image is not set: %w", err)
	}

	addrMapper := biosimage.PhysMemMapper{}
	if _, err = addrMapper.Resolve(biosImg, mrs...); err != nil {
		return nil, fmt.Errorf("unable to find where the memory ranges are mapped to; it is not to BIOS image, but I do not know how to map anything else, yet: %w", err)
	}

	return &types.Data{
		References: []types.Reference{{
			Artifact:      biosImg,
			AddressMapper: addrMapper,
			Ranges:        pkgbytes.Ranges(mrs),
		}},
	}, nil
}

// String implements fmt.Stringer.
func (mrs MemRanges) String() string {
	return fmt.Sprintf("MemRanges(%s)", mrs.rangesString())
}

func (mrs MemRanges) rangesString() string {
	var result []string
	for _, r := range mrs {
		result = append(result, fmt.Sprintf("%08X:%08X", r.Offset, r.End()-1))
	}
	return strings.Join(result, ",")
}
