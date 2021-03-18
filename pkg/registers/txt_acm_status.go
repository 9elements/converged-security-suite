package registers

import (
	"bytes"
	"encoding/binary"
)

const ACMStatusRegisterID RegisterID = "ACM_STATUS"
const ACMStatusRegisterOffset = 0x328

//ACMStatus holds the decoded ACM run state
type ACMStatus uint32

func (reg ACMStatus) ID() RegisterID {
	return ACMStatusRegisterID
}

func (reg ACMStatus) BitSize() uint8 {
	return 64
}

func (reg ACMStatus) Fields() []Field {
	fieldsRaw := []fieldDescription{
		{
			name:      "Module Type",
			bitOffset: 0,
		},
		{
			name:      "Class Code",
			bitOffset: 4,
		},
		{
			name:      "Major Error Code",
			bitOffset: 10,
		},
		{
			name:      "ACM_Started",
			bitOffset: 15,
		},
		{
			name:      "Minor Error Code",
			bitOffset: 16,
		},
		{
			name:      "<reserved>",
			bitOffset: 28,
		},
		{
			name:      "Valid",
			bitOffset: 31,
		},
	}
	return calculateRegisterFields(reg.Raw(), reg.BitSize(), fieldsRaw)
}

func (reg ACMStatus) Raw() uint64 {
	return uint64(reg)
}

func (reg ACMStatus) String() string {
	panic("Not implemented")
}

func (reg ACMStatus) ModuleType() uint8 {
	return uint8(reg & 0xF)
}

func (reg ACMStatus) ClassCode() uint8 {
	return uint8((reg >> 4) & 0x3f)
}

func (reg ACMStatus) MajorErrorCode() uint8 {
	return uint8((reg >> 10) & 0x1f)
}

func (reg ACMStatus) ACMStarted() bool {
	return (reg>>15)&1 == 1
}

func (reg ACMStatus) MinorErrorCode() uint16 {
	return uint16((reg >> 16) & 0xfff)
}

func (reg ACMStatus) Valid() bool {
	return (reg>>31)&1 == 1
}

var _ RawRegister64 = ParseACMStatusRegister(0)

// ReadACMStatusRegister reads the raw ACM status register from TXT config
func ReadACMStatusRegister(data TXTConfigSpace) (ACMStatus, error) {
	var u32 uint32
	buf := bytes.NewReader(data[ACMStatusRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)
	if err != nil {
		return 0, err
	}
	return ACMStatus(u32), nil
}

// ParseACMStatusRegister returns ACMStatus from a raw 64bit value
func ParseACMStatusRegister(raw uint64) ACMStatus {
	return ACMStatus(raw)
}

// FindACMStatus returns ACMStatus register if found
func FindACMStatus(regs Registers) (ACMStatus, bool) {
	r := regs.Find(ACMStatusRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(ACMStatus), true
}
