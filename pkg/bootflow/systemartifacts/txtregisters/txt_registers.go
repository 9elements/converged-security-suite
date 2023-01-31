package txtregisters

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/xaionaro-go/bytesextra"
)

type TXTRegisters struct {
	registers.Registers
}

func (c TXTRegisters) ReadAt(p []byte, off int64) (n int, err error) {
	for _, r := range c.Registers {
		offset := int64(r.Address() - registers.TxtPublicSpace)
		if offset < 0 {
			return 0, fmt.Errorf("internal error: a non TXT-register %T:%#+v in the TXT-registers collection", r, r)
		}
		l := int64(r.BitSize() / 8)
		if off < offset || off >= offset+l {
			continue
		}

		if off != offset {
			return 0, fmt.Errorf("request address 0x%X is not aligned with register address 0x%X", off, offset)
		}

		var out = bytesextra.NewReadWriteSeeker(p)
		err := binary.Write(out, binary.LittleEndian, r.Value())
		return int(out.CurrentPosition), err
	}

	return 0, fmt.Errorf("the register with address 0x%X was not found", off)
}

func (c TXTRegisters) Size() uint64 {
	return registers.TxtPublicSpaceSize
}

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

func New(rs registers.Registers) *TXTRegisters {
	var c TXTRegisters

	for _, r := range rs {
		if r.Address() >= registers.TxtPublicSpace && r.Address() <= registers.TxtPublicSpace+registers.TxtPublicSpaceSize {
			c.Registers = append(c.Registers, r)
		}
	}

	sort.Slice(c.Registers, func(i, j int) bool {
		return c.Registers[i].Address() < c.Registers[j].Address()
	})
	return &c
}

func Get(state *types.State) (*TXTRegisters, error) {
	return types.GetSystemArtifactByTypeFromState[*TXTRegisters](state)
}

func With(state *types.State, callback func(*TXTRegisters) error) error {
	return types.WithSystemArtifact(state, callback)
}
