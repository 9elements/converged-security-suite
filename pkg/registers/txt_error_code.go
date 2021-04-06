package registers

import (
	"bytes"
	"encoding/binary"
)

const TXTErrorCodeRegisterID RegisterID = "TXT.ERRORCODE"
const TXTErrorCodeRegisterOffset = 0x30

type TXTErrorReporter uint8

const (
	ProcessorTXTErrorReporter TXTErrorReporter = 0
	SoftwareTXTErrorReporter  TXTErrorReporter = 1
)

//TXTErrorCode represents several configurations within the TXT config space
type TXTErrorCode uint32

func (reg TXTErrorCode) ID() RegisterID {
	return TXTErrorCodeRegisterID
}

func (reg TXTErrorCode) Raw() uint32 {
	return uint32(reg)
}

func (reg TXTErrorCode) BitSize() uint8 {
	return 32
}

func (reg TXTErrorCode) Fields() []Field {
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
			name:      "Software Source",
			bitOffset: 15,
		},
		{
			name:      "Type1/Minor Error Code",
			bitOffset: 16,
		},
		{
			name:      "Type1/<reserved> Provides implementation and source specific details on the failure condition",
			bitOffset: 28,
		},
		{
			name:      "Processor (0) /Software (1)",
			bitOffset: 30,
		},
		{
			name:      "Valid",
			bitOffset: 31,
		},
	}
	return calculateRegisterFields(uint64(reg.Raw()), reg.BitSize(), fieldsRaw)
}

func (reg TXTErrorCode) ModuleType() uint8 {
	return uint8((reg >> 0) & 0x7) // 3:0
}

func (reg TXTErrorCode) ClassCode() uint8 {
	return uint8((reg >> 4) & 0x3f) // 9:4
}

func (reg TXTErrorCode) MajorErrorCode() uint8 {
	return uint8((reg >> 10) & 0x1f) // 14:10
}

func (reg TXTErrorCode) SoftwareSource() bool {
	return (reg>>15)&0x1 != 0 // 15
}

func (reg TXTErrorCode) MinorErrorCode() uint16 {
	return uint16((reg >> 16) & 0x3ffff) // 27:16
}

func (reg TXTErrorCode) Type1Reserved() uint8 {
	return uint8((reg >> 28) & 0x3) // 29:28
}

func (reg TXTErrorCode) ProcessorOrSoftwareReporter() TXTErrorReporter {
	if (reg>>30)&0x1 == 0 {
		return ProcessorTXTErrorReporter
	}
	return SoftwareTXTErrorReporter
}

func (reg TXTErrorCode) Valid() bool {
	return (reg>>31)&0x1 != 0 // 31
}

var _ RawRegister32 = ParseTXTErrorCode(0)

// ReadTxtErrorCode reads a TXT.ERRORCODE register from TXT config
func ReadTxtErrorCode(data TXTConfigSpace) (TXTErrorCode, error) {
	var u32 uint32
	buf := bytes.NewReader(data[TXTErrorCodeRegisterOffset:])
	err := binary.Read(buf, binary.LittleEndian, &u32)

	if err != nil {
		return 0, err
	}
	return TXTErrorCode(u32), nil
}

// ParseTXTErrorCode returns TXTErrorCode from a raw 64bit value
func ParseTXTErrorCode(raw uint8) TXTErrorCode {
	return TXTErrorCode(raw)
}

// FindTXTErrorCode returns TXTErrorCode register if found
func FindTXTErrorCode(regs Registers) (TXTErrorCode, bool) {
	r := regs.Find(TXTErrorCodeRegisterID)
	if r == nil {
		return 0, false
	}
	return r.(TXTErrorCode), true
}
