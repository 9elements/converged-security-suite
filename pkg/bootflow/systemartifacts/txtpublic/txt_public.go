package txtpublic

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/xaionaro-go/bytesextra"
)

// TXTPublic is the collection of Intel TXT registers.
type TXTPublic struct {
	registers.Registers
}

// ReadAt implements types.SystemArtifact.
func (c TXTPublic) ReadAt(p []byte, off int64) (n int, err error) {
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

// Size implements types.SystemArtifact.
func (c TXTPublic) Size() uint64 {
	return registers.TxtPublicSpaceSize
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
func New(rs registers.Registers) *TXTPublic {
	var c TXTPublic

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

// Get returns the collection of TXT registers.
func Get(state *types.State) (*TXTPublic, error) {
	return types.GetSystemArtifactByTypeFromState[*TXTPublic](state)
}

// With executes the callback if TXT registers collection is set.
func With(state *types.State, callback func(*TXTPublic) error) error {
	return types.WithSystemArtifact(state, callback)
}
