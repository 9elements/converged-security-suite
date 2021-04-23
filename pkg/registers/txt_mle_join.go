package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTMLEJoinRegisterID RegisterID = "TXT.MLE.JOIN"
const TXTMLEJoinRegisterOffset = 0x290

type TXTMLEJoin uint32

func (reg TXTMLEJoin) ID() RegisterID {
	return TXTMLEJoinRegisterID
}

func (reg TXTMLEJoin) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTMLEJoin) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTMLEJoin) Address() uint64 {
	return TxtPublicSpace + TXTMLEJoinRegisterOffset
}

func (reg TXTMLEJoin) Fields() []Field {
	return []Field{
		{
			Name:      "<reserved>",
			BitOffset: 0,
			BitSize:   reg.BitSize(),
			Value:     NumberToFieldValue(uint64(reg)),
		},
	}
}

var _ RawRegister32 = ParseTXTMLEJoin(0)

// ReadTXTMLEJoin reads a TXTMLEJoin register from TXT config
func ReadTXTMLEJoin(data TXTConfigSpace) (TXTMLEJoin, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTMLEJoinRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return TXTMLEJoin(u32), nil
}

// ParseTXTMLEJoin returns TXTMLEJoin from a raw 64bit value
func ParseTXTMLEJoin(raw uint32) TXTMLEJoin {
	return TXTMLEJoin(raw)
}

// FindTXTMLEJoin returns TXTMLEJoin register if found
func FindTXTMLEJoin(regs Registers) (TXTMLEJoin, bool) {
	r := regs.Find(TXTMLEJoinRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTMLEJoin), true
}
