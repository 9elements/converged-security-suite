package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTVerFSBIfRegisterID RegisterID = "TXT.VER.FSBIF"
const TXTVerFSBIfRegisterOffset = 0x100

type TXTVerFSBIF uint32

func (reg TXTVerFSBIF) ID() RegisterID {
	return TXTVerFSBIfRegisterID
}

func (reg TXTVerFSBIF) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTVerFSBIF) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTVerFSBIF) Address() uint64 {
	return TxtPublicSpace + TXTVerFSBIfRegisterOffset
}

func (reg TXTVerFSBIF) Fields() []Field {
	return []Field{
		{
			Name:      "<reserved>",
			BitOffset: 0,
			BitSize:   reg.BitSize(),
			Value:     NumberToFieldValue(uint64(reg)),
		},
	}
}

var _ RawRegister32 = ParseTXTVerFSBIF(0)

// ReadTXTVerFSBIF reads a TXTVerFSBIF register from TXT config
func ReadTXTVerFSBIF(data TXTConfigSpace) (TXTVerFSBIF, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTVerFSBIfRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return TXTVerFSBIF(u32), nil
}

// ParseTXTVerFSBIF returns TXTVerFSBIF from a raw 64bit value
func ParseTXTVerFSBIF(raw uint32) TXTVerFSBIF {
	return TXTVerFSBIF(raw)
}

// FindTXTVerFSBIF returns TXTVerFSBIF register if found
func FindTXTVerFSBIF(regs Registers) (TXTVerFSBIF, bool) {
	r := regs.Find(TXTVerFSBIfRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTVerFSBIF), true
}
