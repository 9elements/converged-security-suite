package registers

import (
	"bytes"
	"encoding/binary"
)

func init() {
	registry.AddRegister(TXTErrorStatus(0))
}

const TXTErrorStatusRegisterID RegisterID = "TXT.ESTS"
const TXTErrorStatusRegisterOffset = 0x8

type TXTErrorStatus uint8

func (reg TXTErrorStatus) ID() RegisterID {
	return TXTErrorStatusRegisterID
}

// Value returns the raw value wrapped into an interface.
func (reg TXTErrorStatus) Value() interface{} {
	return reg.Raw()
}

func (reg TXTErrorStatus) Raw() uint8 {
	return uint8(reg)
}

func (reg TXTErrorStatus) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTErrorStatus) Address() uint64 {
	return TxtPublicSpace + TXTErrorStatusRegisterOffset
}

func (reg TXTErrorStatus) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "TXT_RESET.STS",
			BitOffset: 0,
		},
		{
			Name:      "<reserved>",
			BitOffset: 1,
		},
	}
	return CalculateRegisterFields(uint64(reg), reg.BitSize(), fieldsRaw)
}

func (reg TXTErrorStatus) Reset() bool {
	return reg&0x1 != 0
}

var _ RawRegister8 = ParseTXTErrorStatus(0)

// ReadTXTErrorStatusRegister reads a txt error status register from TXT config
func ReadTXTErrorStatusRegister(data TXTConfigSpace) (TXTErrorStatus, error) {
	buf := bytes.NewReader(data[TXTErrorStatusRegisterOffset:])
	var u8 uint8
	if err := binary.Read(buf, binary.LittleEndian, &u8); err != nil {
		return 0, err
	}
	return ParseTXTErrorStatus(u8), nil
}

// ParseTXTErrorStatus returns TXTErrorStatus from a raw 64bit value
func ParseTXTErrorStatus(raw uint8) TXTErrorStatus {
	return TXTErrorStatus(raw)
}

// FindTXTErrorStatus returns TXTErrorStatus register if found
func FindTXTErrorStatus(regs Registers) (TXTErrorStatus, bool) {
	r := regs.Find(TXTErrorStatusRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTErrorStatus), true
}
