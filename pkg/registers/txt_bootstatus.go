package registers

import (
	"bytes"
	"encoding/binary"
)

func init() {
	registry.AddRegister(TXTBootStatus(0))
}

const TXTBootStatusRegisterID RegisterID = "TXT.SPAD"
const TXTBootStatusRegisterOffset = 0xA0

type TXTBootStatus uint64

func (reg TXTBootStatus) ID() RegisterID {
	return TXTBootStatusRegisterID
}

// Value returns the raw value wrapped into an interface.
func (reg TXTBootStatus) Value() interface{} {
	return reg.Raw()
}

func (reg TXTBootStatus) Raw() uint64 {
	return uint64(reg)
}

func (reg TXTBootStatus) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTBootStatus) Address() uint64 {
	return TxtPublicSpace + TXTBootStatusRegisterOffset
}

func (reg TXTBootStatus) Fields() []Field {
	fieldsRaw := []FieldDescription{
		{
			Name:      "<reserved>",
			BitOffset: 0,
		},
		{
			Name:      "TXT Startup success",
			BitOffset: 30,
		},
		{
			Name:      "Boot Status",
			BitOffset: 31,
		},
		{
			Name:      "Memory power down executed",
			BitOffset: 47,
		},
		{
			Name:      "Boot Status details",
			BitOffset: 48,
		},
		{
			Name:      "TXT Policy enable",
			BitOffset: 53,
		},
		{
			Name:      "Boot Status details",
			BitOffset: 54,
		},
		{
			Name:      "BIOS trusted",
			BitOffset: 59,
		},
		{
			Name:      "TXT Policy disable",
			BitOffset: 60,
		},
		{
			Name:      "Boot Status details",
			BitOffset: 61,
		},
		{
			Name:      "Indicates ACM authentication error",
			BitOffset: 62,
		},
		{
			Name:      "S-ACM success",
			BitOffset: 63,
		},
	}
	return CalculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

func (reg TXTBootStatus) TXTStartupSuccess() bool {
	return (reg>>30)&0x1 != 0
}

func (reg TXTBootStatus) BootStatus() uint16 {
	return uint16((reg >> 31) & 0xFFFF)
}

func (reg TXTBootStatus) MemoryPowerDownExecuted() bool {
	return (reg>>47)&0x1 != 0
}

func (reg TXTBootStatus) BootStatusDetails() uint8 {
	return uint8((reg >> 48) & 63)
}

func (reg TXTBootStatus) TXTPolicyEnable() bool {
	return (reg>>53)&0x1 != 0
}

func (reg TXTBootStatus) BootStatusDetails2() uint8 {
	return uint8((reg >> 54) & 63)
}

func (reg TXTBootStatus) BIOSTrusted() bool {
	return (reg>>59)&0x1 != 0
}

func (reg TXTBootStatus) TXTPolicyDisable() bool {
	return (reg>>60)&0x1 != 0
}

func (reg TXTBootStatus) BootStatusDetails3() bool {
	return (reg>>61)&0x1 != 0
}

func (reg TXTBootStatus) ACMAuthenticationError() bool {
	return (reg>>62)&0x1 != 0
}

func (reg TXTBootStatus) SACMASuccess() bool {
	return (reg>>63)&0x1 != 0
}

var _ RawRegister64 = ParseTXTBootStatus(0)

// ReadTXTBootStatusRegister reads a txt error status register from TXT config
func ReadTXTBootStatusRegister(data TXTConfigSpace) (TXTBootStatus, error) {
	buf := bytes.NewReader(data[TXTBootStatusRegisterOffset:])
	var u64 uint64
	if err := binary.Read(buf, binary.LittleEndian, &u64); err != nil {
		return 0, err
	}
	return ParseTXTBootStatus(u64), nil
}

// ParseTXTBootStatus returns TXTBootStatus from a raw 64bit value
func ParseTXTBootStatus(raw uint64) TXTBootStatus {
	return TXTBootStatus(raw)
}

// FindTXTBootStatus returns TXTBootStatus register if found
func FindTXTBootStatus(regs Registers) (TXTBootStatus, bool) {
	r := regs.Find(TXTBootStatusRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTBootStatus), true
}
