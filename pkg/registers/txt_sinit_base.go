package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTSINITBaseRegisterID RegisterID = "TXT.SINIT.BASE"
const TXTSINITBaseRegisterOffset = 0x270

type TXTSInitBase uint32

func (reg TXTSInitBase) ID() RegisterID {
	return TXTSINITBaseRegisterID
}

func (reg TXTSInitBase) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTSInitBase) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTSInitBase) Address() uint64 {
	return TxtPublicSpace + TXTSINITBaseRegisterOffset
}

func (reg TXTSInitBase) Fields() []Field {
	return []Field{
		{
			Name:      "<reserved>",
			BitOffset: 0,
			BitSize:   reg.BitSize(),
			Value:     NumberToFieldValue(uint64(reg)),
		},
	}
}

var _ RawRegister32 = ParseTXTSInitBase(0)

// ReadTXTSInitBase reads a TXTSInitBase register from TXT config
func ReadTXTSInitBase(data TXTConfigSpace) (TXTSInitBase, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTSINITBaseRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return TXTSInitBase(u32), nil
}

// ParseTXTSInitBase returns TXTSInitBase from a raw 64bit value
func ParseTXTSInitBase(raw uint32) TXTSInitBase {
	return TXTSInitBase(raw)
}

// FindTXTVerFSBIF returns TXTSInitBase register if found
func FindTXTSInitBase(regs Registers) (TXTSInitBase, bool) {
	r := regs.Find(TXTSINITBaseRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTSInitBase), true
}
