package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTSINITSizeRegisterID RegisterID = "TXT.SINIT.SIZE"
const TXTSINITSizeRegisterOffset = 0x278

type TXTSInitSize uint32

func (reg TXTSInitSize) ID() RegisterID {
	return TXTSINITSizeRegisterID
}

func (reg TXTSInitSize) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTSInitSize) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTSInitSize) Address() uint64 {
	return TxtPublicSpace + TXTSINITSizeRegisterOffset
}

func (reg TXTSInitSize) Fields() []Field {
	return []Field{
		{
			Name:      "<reserved>",
			BitOffset: 0,
			BitSize:   reg.BitSize(),
			Value:     NumberToFieldValue(uint64(reg)),
		},
	}
}

var _ RawRegister32 = ParseTXTSInitSize(0)

// ReadTXTSInitBase reads a TXTSInitSize register from TXT config
func ReadTXTSInitSize(data TXTConfigSpace) (TXTSInitSize, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTSINITSizeRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return TXTSInitSize(u32), nil
}

// ParseTXTSInitSize returns TXTSInitSize from a raw 64bit value
func ParseTXTSInitSize(raw uint32) TXTSInitSize {
	return TXTSInitSize(raw)
}

// FindTXTVerFSBIF returns TXTSInitSize register if found
func FindTXTSInitSize(regs Registers) (TXTSInitSize, bool) {
	r := regs.Find(TXTSINITSizeRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTSInitSize), true
}
