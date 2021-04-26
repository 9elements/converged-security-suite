package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTVerEMIfRegisterID RegisterID = "TXT.VER.EMIF"
const TXTVerEMIfRegisterOffset = 0x200

type TXTVerEMIF uint32

func (reg TXTVerEMIF) ID() RegisterID {
	return TXTVerEMIfRegisterID
}

func (reg TXTVerEMIF) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTVerEMIF) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTVerEMIF) Address() uint64 {
	return TxtPublicSpace + TXTVerEMIfRegisterOffset
}

func (reg TXTVerEMIF) Fields() []Field {
	return []Field{
		{
			Name:      "<reserved>",
			BitOffset: 0,
			BitSize:   reg.BitSize(),
			Value:     NumberToFieldValue(uint64(reg)),
		},
	}
}

var _ RawRegister32 = ParseTXTVerEMIF(0)

// ReadTXTVerEMIF reads a TXTVerEMIF register from TXT config
func ReadTXTVerEMIF(data TXTConfigSpace) (TXTVerEMIF, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTVerEMIfRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return TXTVerEMIF(u32), nil
}

// ParseTXTVerEMIF returns TXTVerEMIF from a raw 64bit value
func ParseTXTVerEMIF(raw uint32) TXTVerEMIF {
	return TXTVerEMIF(raw)
}

// FindTXTVerEMIF returns TXTVerEMIF register if found
func FindTXTVerEMIF(regs Registers) (TXTVerEMIF, bool) {
	r := regs.Find(TXTVerEMIfRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTVerEMIF), true
}
