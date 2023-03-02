package amdregisters

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/xaionaro-go/bytesextra"
)

// AMDRegisters is the collection of Intel TXT registers.
type AMDRegisters struct {
	registers.Registers
}

// ReadAt implements types.SystemArtifact.
func (rs AMDRegisters) ReadAt(p []byte, offset int64) (n int, err error) {
	var out = bytesextra.NewReadWriteSeeker(p)

	curOffset := int64(0)
	for _, r := range rs.Registers {
		if curOffset != offset {
			curOffset += int64((r.BitSize() + 7) / 8)
			continue
		}

		err = binary.Write(out, binary.LittleEndian, r.Value())
		n = int(out.CurrentPosition)
		if n >= len(p) {
			return
		}
	}

	return 0, fmt.Errorf("register with offset %d was not found", offset)
}

// Size implements types.SystemArtifact.
func (rs AMDRegisters) Size() uint64 {
	size := uint64(0)
	for _, r := range rs.Registers {
		size += uint64((r.BitSize() + 7) / 8)
	}
	return size
}

// GetRegister sets to `out` the value of the register (which is defined by its type).
func GetRegister[R registers.Register](s *types.State, out *R) error {
	c, err := Get(s)
	if err != nil {
		return fmt.Errorf("unable to get the TXT-registers collection: %w", err)
	}

	registerID := (*out).ID()
	for _, r := range c.Registers {
		if r.ID() == registerID {
			*out = r.(R)
			return nil
		}
	}

	return fmt.Errorf("unable to find register %T in the TXT-registers collection", *out)
}

// New collects TXT registers and returns them as a SystemArtifact.
func New(_rs registers.Registers) *AMDRegisters {
	var rs AMDRegisters

	for _, r := range _rs {
		switch r.ID() {
		case registers.MP0C2PMSG37RegisterID:
		case registers.MP0C2PMSG38RegisterID:
		default:
			continue
		}
		rs.Registers = append(rs.Registers, r)
	}

	sort.Slice(rs.Registers, func(i, j int) bool {
		return rs.Registers[i].ID() < rs.Registers[j].ID()
	})
	return &rs
}

// Get returns the collection of TXT registers.
func Get(state *types.State) (*AMDRegisters, error) {
	return types.GetSystemArtifactByTypeFromState[*AMDRegisters](state)
}

// With executes the callback if TXT registers collection is set.
func With(state *types.State, callback func(*AMDRegisters) error) error {
	return types.WithSystemArtifact(state, callback)
}
