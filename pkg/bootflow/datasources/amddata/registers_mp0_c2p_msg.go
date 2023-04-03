package amddata

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/amdregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

type RegistersMP0C2PMsg struct{}

var _ types.DataSource = (*RegistersMP0C2PMsg)(nil)

// Data implements types.DataSource.
func (RegistersMP0C2PMsg) Data(ctx context.Context, s *types.State) (*types.Data, error) {
	rs, err := amdregisters.Get(s)
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD registers: %w", err)
	}

	var ranges pkgbytes.Ranges
	for _, regID := range []registers.RegisterID{
		registers.MP0C2PMSG37RegisterID,
		registers.MP0C2PMSG38RegisterID,
	} {
		// TODO: remove this hackery, when these registers will be assigned addresses
		offset := uint64(0)
		for _, r := range rs.Registers {
			size := uint64(r.BitSize() / 8)
			if r.ID() != regID {
				offset += size
				continue
			}
			ranges = append(ranges, pkgbytes.Range{
				Offset: offset,
				Length: size,
			})
			break
		}
	}

	return types.NewReferenceData(&types.Reference{
		Artifact: rs,
		Ranges:   ranges,
	}), nil
}

func (RegistersMP0C2PMsg) String() string {
	return "RegistersMP0C2PMsg"
}
