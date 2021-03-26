package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTBootStatusRegisterID RegisterID = "TXT.SPAD"
const TXTBootStatusRegisterOffset = 0xA0

type TXTBootStatus uint64

func (reg TXTBootStatus) ID() RegisterID {
	return TXTBootStatusRegisterID
}

func (reg TXTBootStatus) Raw() uint64 {
	return uint64(reg)
}

func (reg TXTBootStatus) BitSize() uint8 {
	return uint8(binary.Size(reg) * 8)
}

func (reg TXTBootStatus) Fields() []Field {
	fieldsRaw := []fieldDescription{
		{
			name:      "<reserved>",
			bitOffset: 0,
		},
		{
			name:      "TXT Startup success",
			bitOffset: 30,
		},
		{
			name:      "Boot Status",
			bitOffset: 31,
		},
		{
			name:      "Memory power down executed",
			bitOffset: 47,
		},
		{
			name:      "Boot Status details",
			bitOffset: 48,
		},
		{
			name:      "TXT Policy enable",
			bitOffset: 53,
		},
		{
			name:      "Boot Status details",
			bitOffset: 54,
		},
		{
			name:      "BIOS trusted",
			bitOffset: 59,
		},
		{
			name:      "TXT Policy disable",
			bitOffset: 60,
		},
		{
			name:      "Boot Status details",
			bitOffset: 61,
		},
		{
			name:      "Indicates ACM authentication error",
			bitOffset: 62,
		},
		{
			name:      "S-ACM success",
			bitOffset: 63,
		},
	}
	return calculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
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
