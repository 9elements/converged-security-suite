package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTHeapSizeRegisterID RegisterID = "TXT.HEAP.SIZE"
const TXTHeapSizeRegisterOffset = 0x308

type TXTHeapSize uint32

func (reg TXTHeapSize) ID() RegisterID {
	return TXTHeapSizeRegisterID
}

func (reg TXTHeapSize) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTHeapSize) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTHeapSize) Address() uint64 {
	return TxtPublicSpace + TXTHeapSizeRegisterOffset
}

func (reg TXTHeapSize) Fields() []Field {
	return []Field{
		{
			Name:      "<reserved>",
			BitOffset: 0,
			BitSize:   reg.BitSize(),
			Value:     NumberToFieldValue(uint64(reg)),
		},
	}
}

var _ RawRegister32 = ParseTXTHeapSize(0)

// ReadTXTHeapSize reads a TXTHeapSize register from TXT config
func ReadTXTHeapSize(data TXTConfigSpace) (TXTHeapSize, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTHeapSizeRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return TXTHeapSize(u32), nil
}

// ParseTXTHeapSize returns TXTHeapSize from a raw 64bit value
func ParseTXTHeapSize(raw uint32) TXTHeapSize {
	return TXTHeapSize(raw)
}

// FindTXTHeapSize returns TXTHeapSize register if found
func FindTXTHeapSize(regs Registers) (TXTHeapSize, bool) {
	r := regs.Find(TXTHeapSizeRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTHeapSize), true
}
