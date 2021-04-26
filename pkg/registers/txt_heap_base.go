package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTHeapBaseRegisterID RegisterID = "TXT.HEAP.BASE"
const TXTHeapBaseRegisterOffset = 0x300

type TXTHeapBase uint32

func (reg TXTHeapBase) ID() RegisterID {
	return TXTHeapBaseRegisterID
}

func (reg TXTHeapBase) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTHeapBase) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTHeapBase) Address() uint64 {
	return TxtPublicSpace + TXTHeapBaseRegisterOffset
}

func (reg TXTHeapBase) Fields() []Field {
	return []Field{
		{
			Name:      "<reserved>",
			BitOffset: 0,
			BitSize:   reg.BitSize(),
			Value:     NumberToFieldValue(uint64(reg)),
		},
	}
}

var _ RawRegister32 = ParseTXTHeapBase(0)

// ReadTXTHeapBase reads a TXTMLEJoin register from TXT config
func ReadTXTHeapBase(data TXTConfigSpace) (TXTHeapBase, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTHeapBaseRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return TXTHeapBase(u32), nil
}

// ParseTXTHeapBase returns TXTHeapBase from a raw 64bit value
func ParseTXTHeapBase(raw uint32) TXTHeapBase {
	return TXTHeapBase(raw)
}

// FindTXTHeapBase returns TXTHeapBase register if found
func FindTXTHeapBase(regs Registers) (TXTHeapBase, bool) {
	r := regs.Find(TXTHeapBaseRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTHeapBase), true
}
